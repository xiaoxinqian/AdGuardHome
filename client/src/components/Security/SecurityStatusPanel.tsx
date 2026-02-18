import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import api from '../../api/Api';

interface SecurityStatus {
    totp_enabled: boolean;
    password_policy: boolean;
    custom_path: boolean;
    session_timeout_minutes: number;
    max_login_attempts: number;
    notify_enabled: boolean;
    audit_enabled: boolean;
    dns_whitelist_count: number;
}

const SecurityStatusPanel = () => {
    const { t } = useTranslation();
    const [status, setStatus] = useState<SecurityStatus | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchStatus();
    }, []);

    const fetchStatus = async () => {
        try {
            const result = await api.getSecurityStatus();
            setStatus(result);
        } catch (error) {
            console.error('Failed to fetch security status:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return <div className="security-status security-status--loading">{t('loading')}</div>;
    }

    if (!status) {
        return null;
    }

    const statusItems = [
        { key: 'totp', label: t('totp_enable'), value: status.totp_enabled, type: 'boolean' },
        { key: 'password_policy', label: t('password_policy'), value: status.password_policy, type: 'boolean' },
        { key: 'custom_path', label: t('custom_admin_path'), value: status.custom_path, type: 'boolean' },
        { key: 'session_timeout', label: t('session_timeout'), value: status.session_timeout_minutes, type: 'minutes' },
        { key: 'max_attempts', label: t('max_login_attempts'), value: status.max_login_attempts, type: 'number' },
        { key: 'notify', label: t('security_notifications'), value: status.notify_enabled, type: 'boolean' },
        { key: 'audit', label: t('security_audit_log'), value: status.audit_enabled, type: 'boolean' },
        { key: 'dns_whitelist', label: t('dns_whitelist'), value: status.dns_whitelist_count, type: 'count' },
    ];

    return (
        <div className="security-status-panel">
            <h3>{t('security_settings')}</h3>
            <div className="security-status__list">
                {statusItems.map((item) => (
                    <div key={item.key} className="security-status-item">
                        <span className="security-status-item__label">{item.label}</span>
                        <span className={`security-status-item__value security-status-item__value--${item.type === 'boolean' ? (item.value ? 'enabled' : 'disabled') : 'info'}`}>
                            {item.type === 'boolean' && (item.value ? t('enabled') : t('disabled'))}
                            {item.type === 'minutes' && `${item.value} ${t('minutes')}`}
                            {item.type === 'number' && item.value}
                            {item.type === 'count' && (typeof item.value === 'number' && item.value > 0 ? `${item.value} ${t('items')}` : t('all_allowed'))}
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default SecurityStatusPanel;
