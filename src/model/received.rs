use super::RelayStateParam;

/// Typed received message wrapper.
#[derive(Debug, Clone)]
pub struct Received<Message> {
    message: Message,
    relay_state: RelayStateParam,
}

impl<Message> Received<Message> {
    /// Create a received message wrapper.
    pub fn new(message: Message) -> Self {
        Self {
            message,
            relay_state: RelayStateParam::Absent,
        }
    }

    /// Create a received message wrapper preserving inbound RelayState.
    pub fn with_relay_state(message: Message, relay_state: RelayStateParam) -> Self {
        Self {
            message,
            relay_state,
        }
    }

    /// Borrow the typed message.
    pub fn message(&self) -> &Message {
        &self.message
    }

    /// RelayState parameter received with the message.
    pub fn relay_state(&self) -> &RelayStateParam {
        &self.relay_state
    }

    /// Consume the wrapper and return the typed message.
    pub fn into_message(self) -> Message {
        self.message
    }
}
