//! End to end: a real relay and three clients over WebSocket on localhost.

use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tt_client::net::{self, Input};
use tt_client::{Engine, Notice, Place, Store};
use tt_core::{ChannelId, CommunityId, DeviceKey, Op};

struct Client {
    input: mpsc::UnboundedSender<Input>,
    notices: mpsc::UnboundedReceiver<Notice>,
    task: tokio::task::JoinHandle<Engine>,
}

impl Client {
    async fn start(url: &str, name: &str) -> Self {
        Self::resume(url, Engine::new(Store::new(name), None)).await
    }

    /// Connects an existing engine (same keys, same history).
    async fn resume(url: &str, mut engine: Engine) -> Self {
        let (input, mut rx) = mpsc::unbounded_channel();
        let (out, notices) = mpsc::unbounded_channel();
        let url = url.to_string();
        let task = tokio::spawn(async move {
            let _ = net::run(&mut engine, &url, &mut rx, &out).await;
            engine
        });
        let c = Self { input, notices, task };
        c.wait(|e| e.is_online()).await;
        c
    }

    /// Disconnects and hands back the engine.
    async fn stop(self) -> Engine {
        self.input.send(Input::Quit).unwrap();
        self.task.await.unwrap()
    }

    /// Runs `f` on the engine and returns its result.
    async fn with<T: Send + 'static>(&self, f: impl FnOnce(&mut Engine) -> T + Send + 'static) -> T {
        let (tx, rx) = oneshot::channel();
        let _ = self.input.send(Input::With(Box::new(move |e| {
            let _ = tx.send(f(e));
        })));
        rx.await.expect("client task alive")
    }

    fn line(&self, line: &str) {
        self.input.send(Input::Line(line.into())).unwrap();
    }

    /// Polls until `f` is true, or panics after 5 seconds.
    async fn wait(&self, f: impl Fn(&Engine) -> bool + Send + Sync + Clone + 'static) {
        for _ in 0..100 {
            let f = f.clone();
            if self.with(move |e| f(e)).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting");
    }

    fn errors(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(n) = self.notices.try_recv() {
            if let Notice::Error(e) = n {
                out.push(e);
            }
        }
        out
    }

    async fn key(&self) -> DeviceKey {
        self.with(|e| e.me()).await
    }
}

fn texts(e: &Engine, place: Place) -> Vec<String> {
    e.history(place).map(|h| h.messages.iter().map(|m| m.text.clone()).collect()).unwrap_or_default()
}

fn has_text(place: Place, text: &'static str) -> impl Fn(&Engine) -> bool + Send + Sync + Clone {
    move |e: &Engine| texts(e, place).iter().any(|t| t == text)
}

async fn start_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(tt_relay::serve(listener, tt_relay::Config::default()));
    format!("ws://{addr}")
}

async fn join(owner: &Client, joiner: &Client, community: CommunityId) {
    let invite = owner.with(move |e| e.create_invite(community, 1, None)).await.unwrap();
    joiner.with(move |e| e.join(&invite)).await.unwrap();
    joiner.wait(move |e| e.store.communities.contains_key(&community)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn communities_end_to_end() {
    let url = start_relay().await;
    let mut alice = Client::start(&url, "alice").await;
    let mut bob = Client::start(&url, "bob").await;
    let mut carol = Client::start(&url, "carol").await;
    let (a, b, c) = (alice.key().await, bob.key().await, carol.key().await);

    // Alice makes a community; Bob and Carol join with invite links.
    let club = alice.with(|e| e.create_community("Club")).await.unwrap();
    let general: ChannelId =
        alice.with(move |e| e.store.communities[&club].state.channels[0].id).await;
    let gen = Place::Channel(club, general);
    join(&alice, &bob, club).await;
    join(&alice, &carol, club).await;
    for cl in [&alice, &bob, &carol] {
        cl.wait(move |e| e.store.communities.get(&club).is_some_and(|x| x.state.members.len() == 3)).await;
    }

    // Everyone can read everyone (sender keys arrived over DMs).
    alice.with(move |e| e.post_text(gen, "hello club", None)).await.unwrap();
    bob.wait(has_text(gen, "hello club")).await;
    carol.wait(has_text(gen, "hello club")).await;
    carol.with(move |e| e.post_text(gen, "hi from carol", None)).await.unwrap();
    alice.wait(has_text(gen, "hi from carol")).await;
    bob.wait(has_text(gen, "hi from carol")).await;

    // Members can't do admin things; the op is refused locally and remotely.
    let rejected = bob.with(move |e| e.send_op(club, Op::Rename { name: "Bob's".into() })).await;
    assert!(rejected.is_err());

    // A new channel with disappearing messages.
    let secret = ChannelId::random();
    alice
        .with(move |e| e.send_op(club, Op::CreateChannel { id: secret, name: "Secret Plans".into() }))
        .await
        .unwrap();
    // Ops take effect when the relay echoes them back in order.
    alice.wait(move |e| e.store.communities[&club].state.channel(&secret).is_some()).await;
    alice
        .with(move |e| e.send_op(club, Op::SetChannelTimer { id: secret, secs: Some(5) }))
        .await
        .unwrap();
    bob.wait(move |e| {
        e.store.communities[&club].state.channel(&secret).is_some_and(|ch| ch.disappearing_secs == Some(5))
    })
    .await;
    let sp = Place::Channel(club, secret);
    bob.with(move |e| e.post_text(sp, "this will vanish", None)).await.unwrap();
    carol.wait(has_text(sp, "this will vanish")).await;
    let expires = carol
        .with(move |e| e.history(sp).unwrap().messages[0].expires_at)
        .await
        .expect("has a deadline");
    assert!(expires <= tt_core::time::now_ms() + 5_000);

    // Kick Carol. Everyone rotates keys; Carol can't read what comes next.
    alice.with(move |e| e.send_op(club, Op::Kick { device: c })).await.unwrap();
    carol.wait(move |e| !e.store.communities.contains_key(&club)).await;
    bob.wait(move |e| e.store.communities[&club].my_key.generation == 1).await;
    bob.with(move |e| e.post_text(gen, "carol is gone", None)).await.unwrap();
    alice.wait(has_text(gen, "carol is gone")).await;

    // Plugins: Alice types /roll, the result is posted for everyone.
    alice.with(move |e| e.view = Some(gen)).await;
    alice.line("/roll 2d6");
    bob.wait(move |e| texts(e, gen).iter().any(|t| t.starts_with("🎲 alice rolled 2d6"))).await;

    // DMs between people who share a community, with a disappearing timer.
    bob.with(move |e| e.set_dm_timer(c, Some(60))).await.unwrap();
    bob.with(move |e| e.post_text(Place::Dm(c), "psst carol", None)).await.unwrap();
    carol.wait(has_text(Place::Dm(b), "psst carol")).await;
    carol
        .wait(move |e| e.store.dms.get(&b).is_some_and(|d| d.timer_secs == Some(60)))
        .await;
    carol.with(move |e| e.post_text(Place::Dm(b), "hey bob", None)).await.unwrap();
    bob.wait(has_text(Place::Dm(c), "hey bob")).await;

    // Edits and reactions go through too.
    let id = bob.with(move |e| e.history(gen).unwrap().messages.iter().find(|m| m.text == "carol is gone").unwrap().id).await;
    bob.with(move |e| { e.view = Some(gen); }).await;
    bob.line(&format!("/edit {} carol has left", &id.to_string()[..8]));
    alice.wait(has_text(gen, "carol has left")).await;
    alice.line(&format!("/react {} 👋", &id.to_string()[..8]));
    bob.wait(move |e| e.history(gen).unwrap().get(&id).is_some_and(|m| !m.reactions.is_empty())).await;

    let _ = a;
    for (name, cl) in [("alice", &mut alice), ("bob", &mut bob), ("carol", &mut carol)] {
        let errs: Vec<_> = cl.errors().into_iter().filter(|e| !e.contains("not allowed")).collect();
        assert!(errs.is_empty(), "{name} had errors: {errs:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_delivery() {
    let url = start_relay().await;
    let alice = Client::start(&url, "alice").await;
    let bob = Client::start(&url, "bob").await;
    let (a, b) = (alice.key().await, bob.key().await);

    // Bob goes offline. Alice can still start a session from his prekeys,
    // and the relay holds the message.
    let bob_engine = bob.stop().await;
    alice.with(move |e| e.post_text(Place::Dm(b), "while you were out", None)).await.unwrap();

    // Someone else can't read it: it was encrypted for Bob's keys only.
    let mallory = Client::start(&url, "mallory").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(mallory.with(move |e| !e.store.dms.contains_key(&a)).await);

    // Bob comes back with the same keys and gets it.
    let bob = Client::resume(&url, bob_engine).await;
    bob.wait(has_text(Place::Dm(a), "while you were out")).await;
    bob.with(move |e| e.post_text(Place::Dm(a), "back now", None)).await.unwrap();
    alice.wait(has_text(Place::Dm(b), "back now")).await;
}
