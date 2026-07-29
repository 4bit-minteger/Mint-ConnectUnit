use std::time::Instant;

pub struct RetransmitDirectSender {
    tokens: f64,
    last_refill: Instant,
    max_pps: f64,
    capacity: f64,
    pub sent_direct: u64,
    pub sent_fallback: u64,
}

impl RetransmitDirectSender {
    pub fn new(max_pps: f64) -> Self {
        let max_pps = max_pps.max(50.0);
        let capacity = (max_pps * 0.02).clamp(5.0, 20.0);
        Self {
            tokens: max_pps.min(10.0),
            last_refill: Instant::now(),
            max_pps,
            capacity,
            sent_direct: 0,
            sent_fallback: 0,
        }
    }

    pub fn consume_token(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.max_pps).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn set_max_pps(&mut self, pps: f64) {
        self.max_pps = pps.max(50.0);
        self.capacity = (self.max_pps * 0.02).clamp(5.0, 20.0);
        self.tokens = self.tokens.min(self.capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::RetransmitDirectSender;

    #[test]
    fn token_exhaustion_eventually_falls_back() {
        let mut sender = RetransmitDirectSender::new(50.0);
        let mut denied = 0usize;
        for _ in 0..200 {
            if !sender.consume_token() {
                denied += 1;
            }
        }
        assert!(denied > 0);
    }
}
