//! Jitter-buffered playout for remote-peer transforms.
//!
//! Network packets carrying a remote peer's pose arrive with WebRTC's typical
//! jitter — bursts of 2–3 packets in the same frame, occasional gaps,
//! out-of-order reordering. Reading the latest sample directly into a Bevy
//! `Transform` produces visible stutter for any non-trivial frame rate. This
//! module buffers incoming samples, plays them back at a configurable delay
//! into the past, and interpolates between them with a cubic-Hermite spline
//! for translation and `Quat::slerp` for rotation.
//!
//! The implementation is concrete on [`Vec3`] / [`Quat`] — the only shapes
//! consumers actually use today — rather than generic over a `Lerp + Slerp`
//! trait pair. A future generic version would not subsume this one (the
//! Hermite tangent estimator depends on subtraction in the underlying space)
//! and would cost ergonomic clarity for no current consumer's benefit.
//!
//! # Usage
//!
//! 1. Spawn one [`TransformBuffer`] per remote peer.
//! 2. On each inbound transform packet call [`TransformBuffer::push_sample`]
//!    with the wire-supplied position / rotation and the current time.
//! 3. In a render-rate system, call [`TransformBuffer::smoothed_at`] (or
//!    [`TransformBuffer::latest_snap`] for raw debug mode) and write the
//!    result into the entity's `Transform`.
//!
//! See `examples/smoother_demo.rs` for a runnable end-to-end wiring with
//! intentional packet jitter.
//!
//! # Why a playout delay?
//!
//! Reading the *latest* sample puts the camera right at the bleeding edge of
//! the network. Any single dropped or late packet leaves the buffer empty and
//! the remote pose flatlines until the next arrival. Playing back at
//! `now - render_delay_secs` (default 100 ms) means there is almost always at
//! least one sample on either side of the playout cursor, so single-packet
//! drops are invisible. The cost is a small added latency on top of what the
//! network already imposed — much smaller than the camera jumps it removes.

use bevy::prelude::*;
use std::collections::VecDeque;

/// One pose sample on a remote peer's history line.
#[derive(Clone, Copy, Debug)]
pub struct TransformSample {
    pub position: Vec3,
    pub rotation: Quat,
    /// Seconds since application start, taken from
    /// [`bevy::prelude::Time::elapsed_secs_f64`]. The buffer expects samples
    /// to be roughly monotonic but tolerates short bursts: see
    /// [`TransformBuffer::push_sample`] for the timestamp clamping rule.
    pub timestamp: f64,
}

/// Tunable thresholds for the jitter buffer.
///
/// The defaults are sized for a 60 Hz transform broadcast on a typical
/// internet connection (median RTT around 60 ms, occasional bursts of late
/// packets in the same frame). Reduce `render_delay_secs` for lower-latency
/// LANs; increase `buffer_capacity` if your network produces sustained
/// out-of-order packet trains.
#[derive(Clone, Copy, Debug)]
pub struct SmootherConfig {
    /// Hard cap on the number of samples retained per peer. Once full, the
    /// oldest sample is evicted on each new push. Bounds memory.
    pub buffer_capacity: usize,
    /// Expected interval between transform broadcasts from the sender.
    /// Used by [`TransformBuffer::push_sample`] to assign *playout*
    /// timestamps that don't collapse to dt≈0 when the network delivers a
    /// burst of packets in the same frame.
    pub expected_send_interval_secs: f64,
    /// Cap on how far the assigned playout timestamp may drift ahead of
    /// the local wall clock. If the sender's clock runs faster than ours
    /// the naive `(last + expected).max(now)` rule would push playout
    /// permanently into the future, eventually leaving the spline in an
    /// extrapolation regime and snapping to the earliest sample. Clamp
    /// to `now + max_jitter_drift_secs` to rebase on overrun.
    pub max_jitter_drift_secs: f64,
    /// Playout delay: [`TransformBuffer::smoothed_at`] evaluates the
    /// spline at `now - render_delay_secs`, giving late packets a chance
    /// to arrive before the camera reads their slot. Larger = smoother
    /// under jitter but more added latency.
    pub render_delay_secs: f64,
    /// Reject samples whose position has any component with magnitude
    /// above this bound. `is_finite` alone passes `f32::MAX`, but the
    /// Hermite tangent computation subtracts neighboring samples and can
    /// then overflow to `+Inf`, which propagates NaN through `Quat::slerp`
    /// and into every downstream physics broadphase. Sized so that
    /// arithmetic in `(a.position - b.position) / dt` stays well clear of
    /// the f32 overflow threshold for any plausible playspace.
    pub max_coord_abs: f32,
}

impl Default for SmootherConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 32,
            expected_send_interval_secs: 1.0 / 60.0,
            max_jitter_drift_secs: 0.5,
            render_delay_secs: 0.1,
            max_coord_abs: 1.0e6,
        }
    }
}

/// Per-peer ring buffer of inbound transform samples.
///
/// Inserted as a Bevy [`Component`] alongside the peer's `Transform`. The
/// crate does not register systems for this component — host applications
/// drive [`Self::push_sample`] from their inbound handler and
/// [`Self::smoothed_at`] from a render-rate system, so the smoother can
/// coexist with whatever component filters and run conditions the host
/// already uses for remote peers.
#[derive(Component, Default, Debug)]
pub struct TransformBuffer {
    pub samples: VecDeque<TransformSample>,
}

impl TransformBuffer {
    /// Push an inbound transform packet onto the buffer, applying the
    /// sanity guards described on each field of [`SmootherConfig`].
    ///
    /// Returns `true` if the sample was accepted, `false` if it was
    /// rejected as malformed (non-finite position, magnitude over
    /// [`SmootherConfig::max_coord_abs`], etc.). A rejected sample leaves
    /// the buffer untouched — the next well-formed sample (typically
    /// within ~16 ms at a 60 Hz broadcast rate) will arrive and take its
    /// place.
    ///
    /// The assigned playout timestamp is *not* `now` for non-empty
    /// buffers: it is anchored to the previous sample's timestamp plus
    /// the configured send interval, then clamped against `now` (lower
    /// bound) and `now + max_jitter_drift_secs` (upper bound). This
    /// guarantees the spline never sees `dt → 0` from same-frame bursts
    /// and never drifts unbounded if the sender's clock runs faster than
    /// ours.
    pub fn push_sample(
        &mut self,
        position: Vec3,
        rotation: Quat,
        now: f64,
        cfg: &SmootherConfig,
    ) -> bool {
        // Reject NaN / Inf positions outright.
        if !position.is_finite() {
            return false;
        }
        // is_finite() admits values up to f32::MAX, but the Hermite tangent
        // estimator subtracts neighboring positions and would overflow to
        // +Inf — propagating NaN through every consumer. Clamp to a sane
        // playspace bound. See SmootherConfig::max_coord_abs.
        if position.abs().max_element() > cfg.max_coord_abs {
            return false;
        }
        // Normalise the quaternion before it reaches Quat::slerp later;
        // an unnormalised or NaN quat poisons every dependent transform
        // exactly the same way as a NaN position.
        let rotation = if rotation.is_finite() && rotation.length_squared() > 1e-6 {
            rotation.normalize()
        } else {
            Quat::IDENTITY
        };

        // Assign a *playout* timestamp rather than the raw arrival time.
        // WebRTC data channels frequently deliver bursts of 2–3 packets
        // in the same frame; stamping them all with `now` collapses the
        // spline's dt to ~0 and launches the remote mesh to infinity via
        // a divide-by-near-zero velocity tangent. Anchor to the previous
        // sample plus the expected send interval; clamp the result so it
        // can never drift more than `max_jitter_drift_secs` ahead of `now`.
        let raw_next = match self.samples.back() {
            Some(last) => (last.timestamp + cfg.expected_send_interval_secs).max(now),
            None => now,
        };
        let ceiling = now + cfg.max_jitter_drift_secs;
        let timestamp = raw_next.min(ceiling);

        self.samples.push_back(TransformSample {
            position,
            rotation,
            timestamp,
        });
        while self.samples.len() > cfg.buffer_capacity {
            self.samples.pop_front();
        }
        true
    }

    /// Evaluate the buffer at `now - render_delay_secs` using cubic-Hermite
    /// interpolation for translation and `Quat::slerp` for rotation.
    ///
    /// Returns `None` for an empty buffer. Snaps to the first or last
    /// sample for playout times outside the buffered range — extrapolation
    /// is not attempted because in steady state we always have samples on
    /// both sides of the cursor; running off either end means we have
    /// stopped receiving, in which case freezing on the last known pose
    /// is the right behaviour.
    pub fn smoothed_at(&mut self, now: f64, cfg: &SmootherConfig) -> Option<(Vec3, Quat)> {
        if self.samples.is_empty() {
            return None;
        }
        let render_time = now - cfg.render_delay_secs;

        // Evict samples that are clearly older than render_time so the
        // buffer doesn't grow unbounded on a long-running peer. Keep at
        // least two samples on either side of the cursor so the bracketing
        // search and the central-difference tangent estimator always have
        // neighbors. The 2× factor (with a 0.05 floor for tiny render
        // delays) is the same heuristic the original implementation in
        // symbios-overlands settled on.
        let prune_cutoff = render_time - 2.0 * cfg.render_delay_secs.max(0.05);
        while self.samples.len() > 2
            && self.samples.get(1).map(|s| s.timestamp).unwrap_or(f64::MAX) < prune_cutoff
        {
            self.samples.pop_front();
        }

        let samples = &self.samples;
        if samples.len() == 1 || render_time <= samples.front().unwrap().timestamp {
            let s = samples.front().unwrap();
            return Some((s.position, s.rotation));
        }
        if render_time >= samples.back().unwrap().timestamp {
            let s = samples.back().unwrap();
            return Some((s.position, s.rotation));
        }

        // Walk to the bracketing pair [i, i+1].
        let mut i = 0;
        while i + 1 < samples.len() && samples[i + 1].timestamp < render_time {
            i += 1;
        }
        let a = samples[i];
        let b = samples[i + 1];
        let dt = (b.timestamp - a.timestamp).max(1e-6);
        let t = ((render_time - a.timestamp) / dt).clamp(0.0, 1.0) as f32;

        // Central-difference tangents, falling back to forward/backward
        // differences at the endpoints so the tangent is always defined.
        let dt_f = dt as f32;
        let tangent_a = if i > 0 {
            let prev = samples[i - 1];
            let total = (b.timestamp - prev.timestamp).max(1e-6) as f32;
            (b.position - prev.position) / total * dt_f
        } else {
            b.position - a.position
        };
        let tangent_b = if i + 2 < samples.len() {
            let next = samples[i + 2];
            let total = (next.timestamp - a.timestamp).max(1e-6) as f32;
            (next.position - a.position) / total * dt_f
        } else {
            b.position - a.position
        };

        // Cubic Hermite basis. Equivalent to bevy_math::CubicHermite over a
        // single segment but skips the Vec allocation and Result unwrapping
        // that path costs on every frame for every remote peer.
        let t2 = t * t;
        let t3 = t2 * t;
        let h00 = 2.0 * t3 - 3.0 * t2 + 1.0;
        let h10 = t3 - 2.0 * t2 + t;
        let h01 = -2.0 * t3 + 3.0 * t2;
        let h11 = t3 - t2;
        let position = a.position * h00 + tangent_a * h10 + b.position * h01 + tangent_b * h11;
        let rotation = a.rotation.slerp(b.rotation, t);
        Some((position, rotation))
    }

    /// Return the most recently pushed sample's pose, dropping every
    /// older sample. Useful for a "raw" debug mode that bypasses the
    /// jitter buffer entirely so users can see the unfiltered network
    /// quality.
    pub fn latest_snap(&mut self) -> Option<(Vec3, Quat)> {
        let last = self.samples.back().copied()?;
        while self.samples.len() > 1 {
            self.samples.pop_front();
        }
        Some((last.position, last.rotation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SmootherConfig {
        SmootherConfig::default()
    }

    #[test]
    fn rejects_non_finite_position() {
        let mut buf = TransformBuffer::default();
        assert!(!buf.push_sample(Vec3::new(f32::NAN, 0.0, 0.0), Quat::IDENTITY, 0.0, &cfg()));
        assert!(!buf.push_sample(
            Vec3::new(f32::INFINITY, 0.0, 0.0),
            Quat::IDENTITY,
            0.0,
            &cfg()
        ));
        assert!(buf.samples.is_empty());
    }

    #[test]
    fn rejects_oversized_position() {
        let mut buf = TransformBuffer::default();
        let huge = Vec3::splat(2.0e6);
        assert!(!buf.push_sample(huge, Quat::IDENTITY, 0.0, &cfg()));
        assert!(buf.samples.is_empty());
    }

    #[test]
    fn normalises_unnormal_quat() {
        let mut buf = TransformBuffer::default();
        let q = Quat::from_xyzw(2.0, 0.0, 0.0, 0.0);
        assert!(buf.push_sample(Vec3::ZERO, q, 0.0, &cfg()));
        let stored = buf.samples.back().unwrap().rotation;
        assert!((stored.length() - 1.0).abs() < 1e-5);
    }

    #[test]
    fn substitutes_identity_for_degenerate_quat() {
        let mut buf = TransformBuffer::default();
        let zero = Quat::from_xyzw(0.0, 0.0, 0.0, 0.0);
        assert!(buf.push_sample(Vec3::ZERO, zero, 0.0, &cfg()));
        assert_eq!(buf.samples.back().unwrap().rotation, Quat::IDENTITY);
    }

    #[test]
    fn same_frame_burst_does_not_collapse_dt() {
        // Three packets arriving at exactly the same wall-clock instant.
        // Without playout-timestamp anchoring the bracketing pair would
        // span dt≈0 and the spline would explode.
        let mut buf = TransformBuffer::default();
        let cfg = cfg();
        for i in 0..3 {
            buf.push_sample(Vec3::new(i as f32, 0.0, 0.0), Quat::IDENTITY, 1.0, &cfg);
        }
        // Each subsequent push got bumped by `expected_send_interval_secs`.
        let stamps: Vec<f64> = buf.samples.iter().map(|s| s.timestamp).collect();
        assert!(stamps[1] > stamps[0]);
        assert!(stamps[2] > stamps[1]);
    }

    #[test]
    fn timestamp_clamps_to_max_drift() {
        let mut buf = TransformBuffer::default();
        let cfg = SmootherConfig {
            max_jitter_drift_secs: 0.1,
            ..cfg()
        };
        // Seed with an already-future timestamp.
        buf.samples.push_back(TransformSample {
            position: Vec3::ZERO,
            rotation: Quat::IDENTITY,
            timestamp: 100.0,
        });
        // Push at now=10, last timestamp at 100 → raw_next would be 100 + interval,
        // far beyond the ceiling 10 + 0.1 = 10.1.
        buf.push_sample(Vec3::ONE, Quat::IDENTITY, 10.0, &cfg);
        assert!(buf.samples.back().unwrap().timestamp <= 10.1 + 1e-9);
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let mut buf = TransformBuffer::default();
        let cfg = SmootherConfig {
            buffer_capacity: 4,
            ..cfg()
        };
        for i in 0..10 {
            buf.push_sample(
                Vec3::new(i as f32, 0.0, 0.0),
                Quat::IDENTITY,
                i as f64,
                &cfg,
            );
        }
        assert_eq!(buf.samples.len(), 4);
        assert!(buf.samples.front().unwrap().position.x >= 6.0);
    }

    #[test]
    fn smoothed_at_returns_none_when_empty() {
        let mut buf = TransformBuffer::default();
        assert_eq!(buf.smoothed_at(1.0, &cfg()), None);
    }

    #[test]
    fn smoothed_at_snaps_before_first_and_after_last() {
        let mut buf = TransformBuffer::default();
        let cfg = cfg();
        buf.samples.push_back(TransformSample {
            position: Vec3::new(1.0, 0.0, 0.0),
            rotation: Quat::IDENTITY,
            timestamp: 1.0,
        });
        buf.samples.push_back(TransformSample {
            position: Vec3::new(2.0, 0.0, 0.0),
            rotation: Quat::IDENTITY,
            timestamp: 2.0,
        });
        // render_time = 0.0 - 0.1 = -0.1 → before first
        let (pos, _) = buf.smoothed_at(0.0, &cfg).unwrap();
        assert_eq!(pos, Vec3::new(1.0, 0.0, 0.0));
        // render_time = 5.0 - 0.1 = 4.9 → past last
        let (pos, _) = buf.smoothed_at(5.0, &cfg).unwrap();
        assert_eq!(pos, Vec3::new(2.0, 0.0, 0.0));
    }

    #[test]
    fn smoothed_at_interpolates_between_samples() {
        let mut buf = TransformBuffer::default();
        let cfg = SmootherConfig {
            render_delay_secs: 0.0,
            ..cfg()
        };
        buf.samples.push_back(TransformSample {
            position: Vec3::new(0.0, 0.0, 0.0),
            rotation: Quat::IDENTITY,
            timestamp: 0.0,
        });
        buf.samples.push_back(TransformSample {
            position: Vec3::new(10.0, 0.0, 0.0),
            rotation: Quat::IDENTITY,
            timestamp: 1.0,
        });
        // render_time = 0.5, exactly halfway between the two samples.
        let (pos, _) = buf.smoothed_at(0.5, &cfg).unwrap();
        // With only two samples both endpoint tangents fall back to (b - a),
        // so Hermite collapses to plain linear interpolation: x = 5.0.
        assert!((pos.x - 5.0).abs() < 1e-4, "expected ~5, got {pos}");
    }

    #[test]
    fn latest_snap_drops_history() {
        let mut buf = TransformBuffer::default();
        for i in 0..5 {
            buf.samples.push_back(TransformSample {
                position: Vec3::new(i as f32, 0.0, 0.0),
                rotation: Quat::IDENTITY,
                timestamp: i as f64,
            });
        }
        let (pos, _) = buf.latest_snap().unwrap();
        assert_eq!(pos, Vec3::new(4.0, 0.0, 0.0));
        assert_eq!(buf.samples.len(), 1);
    }
}
