//! Fan-out of unsolicited app → extension push frames to every connected
//! client.
//!
//! Each connection registers a bounded channel; the connection thread writes
//! queued pushes between reads. Sending never blocks the GUI or another
//! connection: a slow client is dropped from the registry rather than allowed
//! to stall the app.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::Value;

use crate::protocol::{
    ACTION_DATABASE_CHANGED, ACTION_DATABASE_LOCKED, ACTION_DATABASE_UNLOCKED,
};

/// How many queued pushes a connection may have before it is considered stuck.
const CLIENT_QUEUE_DEPTH: usize = 64;

#[derive(Default)]
pub struct PushHub {
    next_id: AtomicU64,
    clients: Mutex<HashMap<u64, std::sync::mpsc::SyncSender<Value>>>,
}

/// The receiving end of one connection's push channel.
pub struct PushReceiver {
    id: u64,
    rx: std::sync::mpsc::Receiver<Value>,
}

impl PushReceiver {
    /// The registration id, for [`PushHub::unregister`].
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Take the next queued push without blocking.
    pub fn try_recv(&self) -> Option<Value> {
        self.rx.try_recv().ok()
    }
}

impl PushHub {
    /// Register a connection. The returned id is passed back to
    /// [`PushHub::unregister`] when the connection ends.
    pub fn register(&self) -> (u64, PushReceiver) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = std::sync::mpsc::sync_channel(CLIENT_QUEUE_DEPTH);
        if let Ok(mut clients) = self.clients.lock() {
            clients.insert(id, tx);
        }
        (id, PushReceiver { id, rx })
    }

    pub fn unregister(&self, id: u64) {
        if let Ok(mut clients) = self.clients.lock() {
            clients.remove(&id);
        }
    }

    /// Send one frame to every connected client. Clients whose queue is full
    /// or whose socket has gone away are removed.
    pub fn broadcast(&self, frame: &Value) {
        let Ok(mut clients) = self.clients.lock() else {
            return;
        };
        clients.retain(|_, tx| tx.try_send(frame.clone()).is_ok());
    }

    pub fn send_locked(&self) {
        self.broadcast(&serde_json::json!({ "action": ACTION_DATABASE_LOCKED }));
    }

    pub fn send_unlocked(&self) {
        self.broadcast(&serde_json::json!({ "action": ACTION_DATABASE_UNLOCKED }));
    }

    /// `database-changed` is **[friendlypass]**-only and carries the new hash
    /// only when it changed (§5.4).
    pub fn send_changed(&self, hash: Option<&str>) {
        let mut frame = serde_json::json!({ "action": ACTION_DATABASE_CHANGED });
        if let Some(hash) = hash.filter(|hash| !hash.is_empty()) {
            frame["hash"] = Value::String(hash.to_owned());
        }
        self.broadcast(&frame);
    }

    pub fn client_count(&self) -> usize {
        self.clients.lock().map(|clients| clients.len()).unwrap_or(0)
    }
}
