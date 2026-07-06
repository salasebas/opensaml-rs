use super::RelayStateParam;

/// Typed received message wrapper.
#[derive(Debug, Clone)]
pub struct Received<Message> {
    message: Message,
    relay_state: RelayStateParam,
}

impl<Message> Received<Message> {
    /// Create a received message wrapper with absent RelayState.
    pub fn new(message: Message) -> Self {
        Self {
            message,
            relay_state: RelayStateParam::absent(),
        }
    }

    /// Record the RelayState received with the browser message.
    pub fn with_relay_state(mut self, relay_state: RelayStateParam) -> Self {
        self.relay_state = relay_state;
        self
    }

    /// Borrow the typed message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// RelayState received with the browser message.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
    }

    /// Consume the wrapper and return the typed message.
    pub fn into_message(self) -> Message {
        self.message
    }
}
