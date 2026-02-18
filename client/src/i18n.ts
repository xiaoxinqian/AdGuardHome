import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

import zhCN from './__locales/zh-cn.json';
import zhCNServices from './__locales-services/zh-cn.json';

const convertServicesFormat = (
    services: Record<string, { message: string }>,
): Record<string, string> => {
    return Object.fromEntries(
        Object.entries(services).map(([key, value]) => [key, value.message])
    );
};

const resources = {
    'zh-cn': {
        translation: zhCN,
        services: convertServicesFormat(zhCNServices),
    },
};

i18n
    .use(initReactI18next)
    .init({
        resources,
        lng: 'zh-cn',
        fallbackLng: 'zh-cn',
        keySeparator: false,
        nsSeparator: false,
        returnEmptyString: false,
        ns: ['translation', 'services'],
        defaultNS: 'translation',
        interpolation: {
            escapeValue: false,
        },
        react: {
            wait: true,
            bindI18n: 'languageChanged loaded',
        },
    });

export default i18n;
