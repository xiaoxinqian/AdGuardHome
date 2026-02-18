import React, { useState } from 'react';
import { Controller, useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';
import { Input } from '../../components/ui/Controls/Input';
import { validateRequiredValue } from '../../helpers/validators';

export type LoginFormValues = {
    username: string;
    password: string;
    totp?: string;
};

type LoginFormProps = {
    onSubmit: (data: LoginFormValues) => void;
    processing: boolean;
    requireTotp?: boolean;
    lockoutTime?: number;
    error?: string;
};

const Form = ({ onSubmit, processing, requireTotp = false, lockoutTime = 0, error }: LoginFormProps) => {
    const { t } = useTranslation();
    const [showPassword, setShowPassword] = useState(false);

    const {
        handleSubmit,
        control,
        formState: { isValid },
    } = useForm<LoginFormValues>({
        mode: 'onChange',
        defaultValues: {
            username: '',
            password: '',
            totp: '',
        },
    });

    const formatLockoutTime = (seconds: number): string => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}:${secs.toString().padStart(2, '0')}`;
    };

    if (lockoutTime > 0) {
        return (
            <div className="card">
                <div className="card-body p-6">
                    <div className="login-lockout">
                        <div>{t('account_locked')}</div>
                        <div className="login-lockout__timer">
                            {formatLockoutTime(lockoutTime)}
                        </div>
                        <div style={{ fontSize: '14px', marginTop: '8px' }}>
                            {t('lockout_desc')}
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <form onSubmit={handleSubmit(onSubmit)} className="card">
            <div className="card-body p-6">
                {error && (
                    <div className="login-error">
                        {error}
                    </div>
                )}

                {!requireTotp ? (
                    <>
                        <div className="form__group form__group--settings">
                            <Controller
                                name="username"
                                control={control}
                                rules={{ validate: validateRequiredValue }}
                                render={({ field, fieldState }) => (
                                    <Input
                                        {...field}
                                        data-testid="username"
                                        type="text"
                                        label={t('username_label')}
                                        placeholder={t('username_placeholder')}
                                        error={fieldState.error?.message}
                                        autoComplete="username"
                                        autoCapitalize="none"
                                        disabled={processing}
                                    />
                                )}
                            />
                        </div>

                        <div className="form__group form__group--settings" style={{ position: 'relative' }}>
                            <Controller
                                name="password"
                                control={control}
                                rules={{ validate: validateRequiredValue }}
                                render={({ field, fieldState }) => (
                                    <Input
                                        {...field}
                                        data-testid="password"
                                        type={showPassword ? 'text' : 'password'}
                                        label={t('password_label')}
                                        placeholder={t('password_placeholder')}
                                        error={fieldState.error?.message}
                                        autoComplete="current-password"
                                        disabled={processing}
                                    />
                                )}
                            />
                            <button
                                type="button"
                                className="password-toggle"
                                onClick={() => setShowPassword(!showPassword)}
                                tabIndex={-1}
                                aria-label={showPassword ? t('hide_password') : t('show_password')}
                            >
                                {showPassword ? (
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                                        <line x1="1" y1="1" x2="23" y2="23" />
                                    </svg>
                                ) : (
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                                        <circle cx="12" cy="12" r="3" />
                                    </svg>
                                )}
                            </button>
                        </div>
                    </>
                ) : (
                    <div className="form__group form__group--settings">
                        <div className="security-status security-status--info" style={{ marginBottom: '16px' }}>
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                            </svg>
                            <span>{t('totp_required')}</span>
                        </div>

                        <Controller
                            name="totp"
                            control={control}
                            rules={{ 
                                validate: (value) => {
                                    if (!value || value.length !== 6) {
                                        return t('totp_invalid');
                                    }
                                    return true;
                                }
                            }}
                            render={({ field, fieldState }) => (
                                <Input
                                    {...field}
                                    data-testid="totp"
                                    type="text"
                                    label={t('totp_code')}
                                    placeholder="000000"
                                    error={fieldState.error?.message}
                                    autoComplete="one-time-code"
                                    inputMode="numeric"
                                    pattern="[0-9]*"
                                    maxLength={6}
                                    disabled={processing}
                                    className="totp-input"
                                />
                            )}
                        />
                    </div>
                )}

                <div className="form-footer">
                    <button
                        data-testid="sign_in"
                        type="submit"
                        className="btn btn-success btn-block"
                        disabled={processing || !isValid}
                    >
                        {processing && <span className="login__spinner" />}
                        {t('sign_in')}
                    </button>
                </div>
            </div>
        </form>
    );
};

export default Form;
