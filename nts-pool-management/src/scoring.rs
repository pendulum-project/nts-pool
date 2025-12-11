use nts_pool_shared::{KeyExchangeStatus, ProbeResult, SecuredNtpProbeStatus};

#[derive(Debug, Clone, PartialEq)]
pub struct SampleScore {
    pub step: f64,
    pub max_score: Option<f64>,
}

fn offset_step(offset: f64) -> f64 {
    if offset > 0.75 {
        -2.0
    } else if offset > 0.100 {
        0.5 - 1.5 * (offset - 0.100) / (0.750 - 0.100)
    } else if offset > 0.025 {
        1.0 - 0.5 * (offset - 0.025) / (0.100 - 0.025)
    } else {
        1.0
    }
}

pub fn score_sample(sample: &ProbeResult) -> SampleScore {
    if sample.keyexchange.status == KeyExchangeStatus::SrvIpv4Only
        || sample.keyexchange.status == KeyExchangeStatus::SrvIpv6Only
    {
        // Only support for one ip protocol is OK for an SRV pool server.
        SampleScore {
            step: 1.0,
            max_score: None,
        }
    } else if sample.ntp_with_ke_cookie.status == SecuredNtpProbeStatus::Deny
        || sample.ntp_with_ntp_cookie.status == SecuredNtpProbeStatus::Deny
    {
        SampleScore {
            step: -10.0,
            max_score: Some(-50.0),
        }
    } else if sample.keyexchange.status != KeyExchangeStatus::Success
        || sample.ntp_with_ke_cookie.status == SecuredNtpProbeStatus::Timeout
        || sample.ntp_with_ntp_cookie.status == SecuredNtpProbeStatus::Timeout
    {
        SampleScore {
            step: -5.0,
            max_score: None,
        }
    } else if sample.ntp_with_ke_cookie.status != SecuredNtpProbeStatus::Success
        || sample.ntp_with_ntp_cookie.status != SecuredNtpProbeStatus::Success
    {
        SampleScore {
            step: -4.0,
            max_score: None,
        }
    } else if let Some(stratum_ke_cookie) = sample.ntp_with_ke_cookie.stratum
        && let Some(stratum_ntp_cookie) = sample.ntp_with_ntp_cookie.stratum
        && let Some(offset_ke_cookie) = sample.ntp_with_ke_cookie.offset
        && let Some(offset_ntp_cookie) = sample.ntp_with_ntp_cookie.offset
    {
        if stratum_ke_cookie == 0
            || stratum_ntp_cookie == 0
            || !sample.ntp_with_ke_cookie.leap_indicates_synchronized
            || !sample.ntp_with_ntp_cookie.leap_indicates_synchronized
        {
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        } else if offset_ke_cookie.abs() > 3.0 || offset_ntp_cookie.abs() > 3.0 {
            SampleScore {
                step: -4.0,
                max_score: Some(-20.0),
            }
        } else if stratum_ke_cookie >= 8 || stratum_ntp_cookie >= 8 {
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        } else {
            let deduction = if sample.ntp_with_ke_cookie.received_cookies
                < sample.ntp_with_ke_cookie.requested_cookies
                || sample.ntp_with_ntp_cookie.received_cookies
                    < sample.ntp_with_ntp_cookie.requested_cookies
            {
                1.0
            } else {
                0.0
            };
            SampleScore {
                step: (offset_step(offset_ke_cookie) + offset_step(offset_ntp_cookie)) / 2.0
                    - deduction,
                max_score: None,
            }
        }
    } else {
        // Data is not available, so probably something went wrong with the request,
        // even though it is not one of the explicit cases above.
        SampleScore {
            step: -4.0,
            max_score: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use nts_pool_shared::{KeyExchangeProbeResult, SecuredNtpProbeResult};

    use super::*;

    #[test]
    fn test_offset_step_best() {
        assert_eq!(offset_step(0.0), 1.0);
        assert_eq!(offset_step(0.01), 1.0);
        assert_eq!(offset_step(0.025), 1.0);
    }

    #[test]
    fn test_offset_step_okish() {
        assert_eq!(offset_step(0.025), 1.0);
        assert_eq!(offset_step((0.025 + 0.1) / 2.0), 0.75);
        assert_eq!(offset_step(0.1), 0.5);
    }

    #[test]
    fn test_offset_step_bad() {
        assert_eq!(offset_step(0.1), 0.5);
        assert!(offset_step((2.0 * 0.1 + 0.75) / 3.0).abs() < 1e-8);
        assert!((offset_step((0.1 + 2.0 * 0.75) / 3.0) - -0.5).abs() < 1e-8);
        assert_eq!(offset_step(0.75), -1.0);
    }

    #[test]
    fn test_offset_step_horrible() {
        assert_eq!(offset_step(0.751), -2.0);
        assert_eq!(offset_step(1.0), -2.0);
    }

    fn test_ntp_probe_result(stratum: u8, offset: f64) -> SecuredNtpProbeResult {
        SecuredNtpProbeResult {
            status: SecuredNtpProbeStatus::Success,
            request_sent: 0,
            roundtrip_duration: Some(0.1),
            remote_residence_time: Some(0.05),
            offset: Some(offset),
            stratum: Some(stratum),
            leap_indicates_synchronized: true,
            requested_cookies: 1,
            received_cookies: 1,
        }
    }

    fn test_keyexchange_result() -> KeyExchangeProbeResult {
        KeyExchangeProbeResult {
            status: KeyExchangeStatus::Success,
            description: String::new(),
            exchange_start: 0,
            exchange_duration: 0.1,
            num_cookies: 0,
        }
    }

    #[test]
    fn test_perfect_sample() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: KeyExchangeProbeResult {
                    status: KeyExchangeStatus::Success,
                    description: String::new(),
                    exchange_start: 0,
                    exchange_duration: 0.1,
                    num_cookies: 8,
                },
                ntp_with_ke_cookie: test_ntp_probe_result(1, 0.01),
                ntp_with_ntp_cookie: test_ntp_probe_result(1, 0.01),
            }),
            SampleScore {
                step: 1.0,
                max_score: None,
            }
        );
    }

    #[test]
    fn test_failed_keyexchange() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: KeyExchangeProbeResult {
                    status: KeyExchangeStatus::Failed,
                    description: String::new(),
                    exchange_start: 0,
                    exchange_duration: 0.1,
                    num_cookies: 0,
                },
                ntp_with_ke_cookie: test_ntp_probe_result(1, 0.01),
                ntp_with_ntp_cookie: test_ntp_probe_result(1, 0.01),
            }),
            SampleScore {
                step: -5.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: KeyExchangeProbeResult {
                    status: KeyExchangeStatus::Timeout,
                    description: String::new(),
                    exchange_start: 0,
                    exchange_duration: 2.0,
                    num_cookies: 0,
                },
                ntp_with_ke_cookie: test_ntp_probe_result(1, 0.01),
                ntp_with_ntp_cookie: test_ntp_probe_result(1, 0.01),
            }),
            SampleScore {
                step: -5.0,
                max_score: None,
            }
        );
    }

    #[test]
    fn test_failed_ntp_probe() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::DnsLookupFailed,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::NotAttempted,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::NtsNak,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::DnsLookupFailed,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::NotAttempted,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::NtsNak,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );
    }

    #[test]
    fn test_timeout_on_ntp() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::Timeout,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -5.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::Timeout,
                    ..Default::default()
                }
            }),
            SampleScore {
                step: -5.0,
                max_score: None,
            }
        );
    }

    #[test]
    fn test_corrupted_ntp_probe() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    offset: None,
                    ..test_ntp_probe_result(2, 0.1)
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    stratum: None,
                    ..test_ntp_probe_result(2, 0.1)
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    offset: None,
                    ..test_ntp_probe_result(2, 0.1)
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    stratum: None,
                    ..test_ntp_probe_result(2, 0.1)
                }
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );
    }

    #[test]
    fn test_unsynchronized_ntp_probe() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    stratum: Some(0),
                    ..test_ntp_probe_result(2, 0.01)
                },
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    leap_indicates_synchronized: false,
                    ..test_ntp_probe_result(2, 0.01)
                },
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    stratum: Some(8),
                    ..test_ntp_probe_result(2, 0.01)
                },
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 15.0),
            }),
            SampleScore {
                step: -4.0,
                max_score: Some(-20.0),
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    stratum: Some(0),
                    ..test_ntp_probe_result(2, 0.01)
                },
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    leap_indicates_synchronized: false,
                    ..test_ntp_probe_result(2, 0.01)
                },
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    stratum: Some(8),
                    ..test_ntp_probe_result(2, 0.01)
                },
            }),
            SampleScore {
                step: -4.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 15.0),
            }),
            SampleScore {
                step: -4.0,
                max_score: Some(-20.0),
            }
        );
    }

    #[test]
    fn test_rapid_backoff_on_deny() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::Deny,
                    ..Default::default()
                },
            }),
            SampleScore {
                step: -10.0,
                max_score: Some(-50.0),
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    status: SecuredNtpProbeStatus::Deny,
                    ..Default::default()
                },
            }),
            SampleScore {
                step: -10.0,
                max_score: Some(-50.0),
            }
        );
    }

    #[test]
    fn both_offsets_contribute() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.01),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
            }),
            SampleScore {
                step: 0.75,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.01),
            }),
            SampleScore {
                step: 0.75,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: test_keyexchange_result(),
                ntp_with_ke_cookie: test_ntp_probe_result(2, 0.1),
                ntp_with_ntp_cookie: test_ntp_probe_result(2, 0.1),
            }),
            SampleScore {
                step: 0.5,
                max_score: None,
            }
        );
    }

    #[test]
    fn deduct_for_nondelivered_cookies() {
        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: KeyExchangeProbeResult {
                    status: KeyExchangeStatus::Success,
                    description: String::new(),
                    exchange_start: 0,
                    exchange_duration: 0.1,
                    num_cookies: 8,
                },
                ntp_with_ke_cookie: test_ntp_probe_result(1, 0.01),
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    requested_cookies: 2,
                    received_cookies: 1,
                    ..test_ntp_probe_result(1, 0.01)
                }
            }),
            SampleScore {
                step: 0.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: KeyExchangeProbeResult {
                    status: KeyExchangeStatus::Success,
                    description: String::new(),
                    exchange_start: 0,
                    exchange_duration: 0.1,
                    num_cookies: 8,
                },
                ntp_with_ntp_cookie: test_ntp_probe_result(1, 0.01),
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    requested_cookies: 2,
                    received_cookies: 1,
                    ..test_ntp_probe_result(1, 0.01)
                }
            }),
            SampleScore {
                step: 0.0,
                max_score: None,
            }
        );

        assert_eq!(
            score_sample(&ProbeResult {
                keyexchange: KeyExchangeProbeResult {
                    status: KeyExchangeStatus::Success,
                    description: String::new(),
                    exchange_start: 0,
                    exchange_duration: 0.1,
                    num_cookies: 8,
                },
                ntp_with_ke_cookie: SecuredNtpProbeResult {
                    requested_cookies: 2,
                    received_cookies: 1,
                    ..test_ntp_probe_result(1, 0.01)
                },
                ntp_with_ntp_cookie: SecuredNtpProbeResult {
                    requested_cookies: 2,
                    received_cookies: 1,
                    ..test_ntp_probe_result(1, 0.01)
                }
            }),
            SampleScore {
                step: 0.0,
                max_score: None,
            }
        );
    }
}
