import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import api from '../../api/Api';

interface SecurityCheck {
    name: string;
    passed: boolean;
    description: string;
}

interface SecurityScoreData {
    score: number;
    max_score: number;
    level: string;
    checks: SecurityCheck[];
    suggestions: string[];
}

const SecurityScore = () => {
    const { t } = useTranslation();
    const [data, setData] = useState<SecurityScoreData | null>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchSecurityScore();
    }, []);

    const fetchSecurityScore = async () => {
        try {
            const result = await api.getSecurityScore();
            setData(result);
        } catch (error) {
            console.error('Failed to fetch security score:', error);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="security-score security-score--loading">
                <div className="security-score__spinner" />
                <span>{t('loading')}</span>
            </div>
        );
    }

    if (!data) {
        return null;
    }

    const getScoreColor = (score: number) => {
        if (score >= 80) return '#28a745';
        if (score >= 60) return '#17a2b8';
        if (score >= 40) return '#ffc107';
        return '#dc3545';
    };

    const scoreColor = getScoreColor(data.score);
    const scorePercentage = (data.score / data.max_score) * 100;

    return (
        <div className="security-score">
            <div className="security-score__header">
                <h3>{t('security_score')}</h3>
                <span className="security-score__level" style={{ color: scoreColor }}>
                    {data.level}
                </span>
            </div>

            <div className="security-score__meter">
                <div className="security-score__meter-bg">
                    <div
                        className="security-score__meter-fill"
                        style={{
                            width: `${scorePercentage}%`,
                            backgroundColor: scoreColor,
                        }}
                    />
                </div>
                <div className="security-score__value">
                    <span style={{ color: scoreColor }}>{data.score}</span>
                    <span className="security-score__max">/{data.max_score}</span>
                </div>
            </div>

            <div className="security-score__checks">
                {data.checks.map((check) => (
                    <div key={check.name} className="security-check">
                        <span className={`security-check__icon security-check__icon--${check.passed ? 'passed' : 'failed'}`}>
                            {check.passed ? '✓' : '✗'}
                        </span>
                        <span className="security-check__description">{check.description}</span>
                    </div>
                ))}
            </div>

            {data.suggestions.length > 0 && (
                <div className="security-score__suggestions">
                    <h4>{t('suggestions')}</h4>
                    <ul>
                        {data.suggestions.map((suggestion, index) => (
                            <li key={index}>{suggestion}</li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
};

export default SecurityScore;
