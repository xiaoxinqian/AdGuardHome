import React from 'react';
import { useTranslation } from 'react-i18next';
import SecurityScore from './SecurityScore';
import SecurityStatusPanel from './SecurityStatusPanel';
import TOTPSetup from './TOTPSetup';
import './SecurityCenter.css';

const SecurityCenter = () => {
    const { t } = useTranslation();

    return (
        <div className="security-center">
            <div className="security-center__header">
                <h2>{t('security_center')}</h2>
            </div>

            <div className="security-center__content">
                <div className="security-center__main">
                    <SecurityScore />
                </div>

                <div className="security-center__sidebar">
                    <SecurityStatusPanel />
                    <TOTPSetup />
                </div>
            </div>
        </div>
    );
};

export default SecurityCenter;
