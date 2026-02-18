import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import api from '../../api/Api';

const TOTPSetup = () => {
    const { t } = useTranslation();
    const [step, setStep] = useState<'intro' | 'setup' | 'verify' | 'done'>('intro');
    const [secret, setSecret] = useState('');
    const [qrCode, setQrCode] = useState<string>('');
    const [verifyCode, setVerifyCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const generateSecret = () => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let result = '';
        for (let i = 0; i < 32; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    };

    const handleStartSetup = () => {
        const newSecret = generateSecret();
        setSecret(newSecret);
        setStep('setup');
    };

    const handleContinue = () => {
        setStep('verify');
    };

    const handleVerify = async () => {
        if (verifyCode.length !== 6) {
            setError(t('totp_invalid'));
            return;
        }

        setLoading(true);
        setError('');

        try {
            await api.enableTOTP(secret, verifyCode);
            setStep('done');
        } catch (err) {
            setError(t('verification_failed'));
        } finally {
            setLoading(false);
        }
    };

    const handleDisable = async () => {
        setLoading(true);
        try {
            await api.disableTOTP();
            setStep('intro');
        } catch (err) {
            setError(t('operation_failed'));
        } finally {
            setLoading(false);
        }
    };

    if (step === 'intro') {
        return (
            <div className="totp-setup">
                <h3>{t('totp_enable')}</h3>
                <p className="totp-setup__desc">{t('totp_setup_desc')}</p>
                <div className="totp-setup__actions">
                    <button className="btn btn-success" onClick={handleStartSetup}>
                        {t('start_setup')}
                    </button>
                </div>
            </div>
        );
    }

    if (step === 'setup') {
        return (
            <div className="totp-setup">
                <h3>{t('totp_scan_qr')}</h3>
                <div className="totp-setup__secret">
                    <label>{t('secret_key')}</label>
                    <code>{secret}</code>
                </div>
                <p className="totp-setup__hint">{t('totp_manual_entry_hint')}</p>
                <div className="totp-setup__actions">
                    <button className="btn btn-primary" onClick={handleContinue}>
                        {t('continue')}
                    </button>
                </div>
            </div>
        );
    }

    if (step === 'verify') {
        return (
            <div className="totp-setup">
                <h3>{t('totp_enter_code')}</h3>
                <div className="totp-setup__input">
                    <input
                        type="text"
                        maxLength={6}
                        value={verifyCode}
                        onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ''))}
                        placeholder="000000"
                        className="form-control totp-input"
                        inputMode="numeric"
                        pattern="[0-9]*"
                    />
                </div>
                {error && <div className="totp-setup__error">{error}</div>}
                <div className="totp-setup__actions">
                    <button
                        className="btn btn-success"
                        onClick={handleVerify}
                        disabled={verifyCode.length !== 6 || loading}
                    >
                        {loading ? t('verifying') : t('verify')}
                    </button>
                    <button className="btn btn-secondary" onClick={() => setStep('setup')}>
                        {t('back')}
                    </button>
                </div>
            </div>
        );
    }

    if (step === 'done') {
        return (
            <div className="totp-setup">
                <h3>{t('totp_enabled_success')}</h3>
                <p>{t('totp_enabled_desc')}</p>
                <div className="totp-setup__actions">
                    <button className="btn btn-danger" onClick={handleDisable}>
                        {t('totp_disable')}
                    </button>
                </div>
            </div>
        );
    }

    return null;
};

export default TOTPSetup;
