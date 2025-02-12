def get_defense_actions(attack_type, severity):
    defense_actions = {
        'mitm': {
            'high': {
                'terminate_connections': {
                    'connection_ids': ['active_connections'],
                    'force_disconnect': True,
                    'reason': 'Suspected MITM attack'
                },
                'enforce_encryption': {
                    'protocol': 'TLS 1.3',
                    'cipher_suites': ['ECDHE-ECDSA-AES256-GCM-SHA384'],
                    'duration': 3600,  # seconds
                    'certificate_pinning': True
                },
                'revoke_certificates': {
                    'cert_ids': ['compromised_certificates'],
                    'reissue_policy': 'immediate',
                    'notification': True
                },
                'alert_security_team': {
                    'severity': 'high',
                    'attack_type': 'mitm',
                    'affected_systems': ['system_ids'],
                    'network_segment': 'segment_id'
                }
            },
            'medium': {
                'enable_certificate_validation': {
                    'validation_level': 'strict',
                    'check_frequency': 300,  # seconds
                    'revocation_check': True
                },
                'implement_packet_filtering': {
                    'filter_rules': ['suspicious_packets'],
                    'duration': 1800,
                    'log_matches': True
                }
            },
            'low': {
                'monitor_traffic_patterns': {
                    'metrics': ['packet_loss', 'latency', 'route_changes'],
                    'interval': 60,  # seconds
                    'baseline_comparison': True
                }
            }
        },

        'xss': {
            'high': {
                'sanitize_input': {
                    'input_fields': ['affected_fields'],
                    'sanitization_rules': ['html_encode', 'script_remove'],
                    'log_violations': True
                },
                'implement_csp': {
                    'policies': {
                        'script-src': "'self'",
                        'style-src': "'self'",
                        'frame-ancestors': "'none'"
                    },
                    'report_uri': '/csp-report'
                },
                'session_invalidation': {
                    'affected_sessions': ['session_ids'],
                    'force_logout': True,
                    'require_reauthentication': True
                }
            },
            'medium': {
                'enable_waf_rules': {
                    'rule_set': 'xss_protection',
                    'mode': 'block',
                    'duration': 7200
                },
                'content_security_monitoring': {
                    'monitor_endpoints': ['affected_urls'],
                    'check_interval': 300,
                    'alert_threshold': 5
                }
            },
            'low': {
                'log_suspicious_inputs': {
                    'input_patterns': ['script_tags', 'suspicious_urls'],
                    'log_level': 'warning',
                    'retention_period': 30  # days
                }
            }
        },

        'dos': {
            'high': {
                'rate_limiting': {
                    'requests_per_second': 100,
                    'burst_size': 200,
                    'window_size': 60  # seconds
                },
                'traffic_filtering': {
                    'filter_rules': ['rate_threshold', 'packet_pattern'],
                    'action': 'drop',
                    'duration': 3600
                },
                'resource_scaling': {
                    'resource_type': ['cpu', 'memory', 'bandwidth'],
                    'scale_factor': 2.0,
                    'auto_scale': True
                }
            },
            'medium': {
                'connection_throttling': {
                    'max_connections': 1000,
                    'per_ip_limit': 50,
                    'timeout': 300
                },
                'request_validation': {
                    'validate_parameters': True,
                    'check_payload_size': True,
                    'max_payload_size': 1024  # KB
                }
            },
            'low': {
                'monitor_resources': {
                    'metrics': ['cpu_usage', 'memory_usage', 'network_traffic'],
                    'interval': 60,
                    'alert_threshold': 0.8  # 80%
                }
            }
        },

        'ddos': {
            'high': {
                'blackhole_routing': {
                    'affected_ips': ['attack_sources'],
                    'duration': 7200,
                    'route_type': 'null_route'
                },
                'traffic_scrubbing': {
                    'scrubbing_centers': ['center_ids'],
                    'filtering_rules': ['volumetric', 'protocol_anomaly'],
                    'clean_traffic_only': True
                },
                'anycast_distribution': {
                    'enable_distribution': True,
                    'pod_locations': ['datacenter_ids'],
                    'load_balancing': 'round_robin'
                }
            },
            'medium': {
                'syn_cookie_protection': {
                    'enable': True,
                    'cookie_lifetime': 60,
                    'threshold': 1000  # connections per second
                },
                'rate_limiting': {
                    'bandwidth_limit': '10Gbps',
                    'packet_rate_limit': 1000000,
                    'duration': 3600
                }
            },
            'low': {
                'traffic_analysis': {
                    'metrics': ['packet_distribution', 'protocol_ratio'],
                    'interval': 300,
                    'baseline_deviation': 0.2
                }
            }
        },

        'injection': {
            'high': {
                'input_validation': {
                    'validation_rules': ['sql', 'nosql', 'ldap', 'xpath'],
                    'sanitization_level': 'strict',
                    'block_malicious': True
                },
                'query_parameterization': {
                    'enforce': True,
                    'log_violations': True,
                    'alert_threshold': 5
                },
                'database_access_control': {
                    'restrict_permissions': True,
                    'read_only_mode': True,
                    'duration': 3600
                }
            },
            'medium': {
                'error_suppression': {
                    'hide_details': True,
                    'custom_error_pages': True,
                    'log_full_errors': True
                },
                'query_monitoring': {
                    'monitor_patterns': ['union_select', 'exec_commands'],
                    'alert_threshold': 3,
                    'block_duration': 900
                }
            },
            'low': {
                'log_queries': {
                    'log_level': 'info',
                    'include_parameters': True,
                    'retention_days': 30
                }
            }
        },

        'scanning': {
            'high': {
                'port_shutdown': {
                    'affected_ports': ['detected_ports'],
                    'duration': 3600,
                    'whitelist': ['essential_services']
                },
                'dynamic_ip_blocking': {
                    'block_duration': 7200,
                    'threshold': 50,  # scan attempts
                    'scope': 'subnet'
                },
                'service_masking': {
                    'hide_versions': True,
                    'fake_services': True,
                    'masking_duration': 86400
                }
            },
            'medium': {
                'scan_detection': {
                    'detection_rules': ['port_sweep', 'version_probe'],
                    'threshold': 20,
                    'window_size': 300
                },
                'service_hardening': {
                    'minimize_information': True,
                    'remove_banners': True,
                    'restricted_access': True
                }
            },
            'low': {
                'activity_logging': {
                    'log_connections': True,
                    'log_queries': True,
                    'retention_period': 30
                }
            }
        }
    }
    
    return defense_actions.get(attack_type, {}).get(severity, {})