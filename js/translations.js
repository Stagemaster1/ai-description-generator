/**
 * PLYVO RECOVERY - Session 3: JavaScript Modularization
 *
 * 🧱 CODEBASE ARCHITECT - Translation Dictionaries Module
 *
 * ARCHITECTURAL CHANGE: JavaScript Externalization - Translations
 * - Extracted from embedded script block (lines 298-1200)
 * - Implements CSP-compliant modular structure
 * - Maintains all language support functionality
 *
 * AUDIT TRAIL:
 * - Change Type: Modular extraction from embedded script
 * - Source: index.html lines 298-1200 (translations object)
 * - Rationale: CSP compliance and code organization
 * - Reversible: Yes, can re-embed if needed
 * - Containment: Preserved within js/ directory structure
 *
 * Date: 2025-09-28
 * Session: 3
 * Architect: Codebase Architect under Copilot supervision
 */

// Translation dictionaries for internationalization
const translations = {
    en: {
        // Header
        pageTitle: 'SolTecSol - AI Product Description Generator',
        companyName: 'SolTecSol',
        appTitle: 'AI Description Generator',
        subscriptionPlans: 'Subscription Plans',
        createAccount: 'Create Account',
        signIn: 'Sign In',
        tagline: 'Transform Product URLs into Converting Copy',
        subtitle: 'Generate SEO-optimized, brand-specific product descriptions that convert browsers into buyers. Save hours of writing time and boost your e-commerce sales.',

        // Generator Section
        generateSection: 'Generate Your Description',
        monthlyUsage: 'Monthly Usage',
        usedDescriptions: 'descriptions used',
        freeDescriptions: 'free descriptions used',
        of: 'of',
        unlimitedDescriptions: 'unlimited',
        usageCounterText: '{{used}} of {{total}} free descriptions used',
        upgradePrompt: 'Upgrade for unlimited descriptions →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Trusted by E-commerce Leaders',
        averageSalesIncrease: 'Average Sales Increase',
        averageTimeSaved: 'Average Time Saved',
        customerSatisfaction: 'Customer Satisfaction',

        // Input Mode Buttons
        productURL: '🔗 Product URL',
        barcodeUPC: '📊 Barcode/UPC',
        manualEntry: '✏️ Manual Entry',

        // Form Labels
        productIdentification: 'Product Identification',
        productUrl: 'Product URL',
        productUrlPlaceholder: 'https://example.com/product-page',
        barcodeNumber: 'Barcode/UPC Number',
        barcodePlaceholder: 'Enter barcode or UPC number',
        lookupProduct: '🔍 Lookup Product',
        productName: 'Product Name',
        productNamePlaceholder: 'Enter product name',
        brand: 'Brand',
        brandPlaceholder: 'Enter brand name',
        category: 'Category',
        categoryPlaceholder: 'e.g., Electronics, Clothing',
        brandTone: 'Brand Tone',
        descriptionLength: 'Description Length',
        language: 'Language',
        targetAudience: 'Target Audience (Optional)',
        targetAudiencePlaceholder: 'e.g., busy parents, fitness enthusiasts, tech professionals',
        keyFeatures: 'Key Features to Highlight (Optional)',
        keyFeaturesPlaceholder: 'List the most important features you want to emphasize...',

        // Brand Tone Options
        selectBrandVoice: 'Select your brand voice...',
        luxuryPremium: 'Luxury & Premium',
        casualFriendly: 'Casual & Friendly',
        professionalAuthoritative: 'Professional & Authoritative',
        funQuirky: 'Fun & Quirky',
        minimalistClean: 'Minimalist & Clean',

        // Length Options
        shortLength: 'Short (50-100 words) - Quick & Punchy',
        mediumLength: 'Medium (150-250 words) - Recommended',
        extensiveLength: 'Extensive (300-500 words) - Detailed',

        // Buttons
        generateDescription: 'Generate AI Description',
        copyToClipboard: '📋 Copy to Clipboard',

        // Results
        optimizedDescription: '✨ Your Optimized Product Description',

        // Stats
        descriptionsGenerated: 'Descriptions Generated',
        happyCustomers: 'Happy Customers',
        timesSaved: 'Hours Saved',

        // Notifications
        descriptionCopied: 'Description copied to clipboard!',
        usageDataRefreshed: 'Usage data refreshed',

        // Language Switcher
        selectLanguage: 'Language',

        // Support Footer
        supportText: 'Need help? Contact our support team',

        // Language Options
        languageOptionEnglish: 'English',
        languageOptionSpanish: 'Spanish',
        languageOptionFrench: 'French',
        languageOptionGerman: 'German',
        languageOptionItalian: 'Italian',
        languageOptionPortugueseBR: 'Portuguese (Brazil)',
        languageOptionDutch: 'Dutch',
        languageOptionJapanese: 'Japanese',
        languageOptionChinese: 'Chinese',
        languageOptionRussian: 'Russian',
        languageOptionArabic: 'Arabic',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Korean'
    },

    es: {
        // Header
        pageTitle: 'SolTecSol - Generador de Descripciones de Productos con IA',
        companyName: 'SolTecSol (Soluciones Tecnológicas Sólidas)',
        appTitle: 'Generador de Descripciones con IA',
        subscriptionPlans: 'Planes de Suscripción',
        createAccount: 'Crear Cuenta',
        signIn: 'Iniciar Sesión',
        tagline: 'Transforma URLs de Productos en Textos que Convierten',
        subtitle: 'Genera descripciones de productos optimizadas para SEO y específicas de marca que convierten navegadores en compradores. Ahorra horas de tiempo de escritura y aumenta tus ventas de comercio electrónico.',

        // Generator Section
        generateSection: 'Genera Tu Descripción',
        monthlyUsage: 'Uso Mensual',
        usedDescriptions: 'descripciones utilizadas',
        freeDescriptions: 'descripciones gratuitas utilizadas',
        of: 'de',
        unlimitedDescriptions: 'ilimitadas',
        usageCounterText: '{{used}} de {{total}} descripciones gratuitas utilizadas',
        upgradePrompt: 'Actualizar para descripciones ilimitadas →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Confianza de Líderes E-commerce',
        averageSalesIncrease: 'Aumento Promedio de Ventas',
        averageTimeSaved: 'Tiempo Promedio Ahorrado',
        customerSatisfaction: 'Satisfacción del Cliente',

        // Input Mode Buttons
        productURL: '🔗 URL del Producto',
        barcodeUPC: '📊 Código de Barras/UPC',
        manualEntry: '✏️ Entrada Manual',

        // Form Labels
        productIdentification: 'Identificación del Producto',
        productUrl: 'URL del Producto',
        productUrlPlaceholder: 'https://ejemplo.com/pagina-producto',
        barcodeNumber: 'Número de Código de Barras/UPC',
        barcodePlaceholder: 'Introduce código de barras o número UPC',
        lookupProduct: '🔍 Buscar Producto',
        productName: 'Nombre del Producto',
        productNamePlaceholder: 'Introduce nombre del producto',
        brand: 'Marca',
        brandPlaceholder: 'Introduce nombre de la marca',
        category: 'Categoría',
        categoryPlaceholder: 'ej., Electrónicos, Ropa',
        brandTone: 'Tono de Marca',
        descriptionLength: 'Longitud de Descripción',
        language: 'Idioma',
        targetAudience: 'Audiencia Objetivo (Opcional)',
        targetAudiencePlaceholder: 'ej., padres ocupados, entusiastas del fitness, profesionales de tecnología',
        keyFeatures: 'Características Clave a Destacar (Opcional)',
        keyFeaturesPlaceholder: 'Lista las características más importantes que quieres enfatizar...',

        // Brand Tone Options
        selectBrandVoice: 'Selecciona la voz de tu marca...',
        luxuryPremium: 'Lujo y Premium',
        casualFriendly: 'Casual y Amigable',
        professionalAuthoritative: 'Profesional y Autoritario',
        funQuirky: 'Divertido y Peculiar',
        minimalistClean: 'Minimalista y Limpio',

        // Length Options
        shortLength: 'Corta (50-100 palabras) - Rápida y Directa',
        mediumLength: 'Mediana (150-250 palabras) - Recomendada',
        extensiveLength: 'Extensa (300-500 palabras) - Detallada',

        // Buttons
        generateDescription: 'Generar Descripción con IA',
        copyToClipboard: '📋 Copiar al Portapapeles',

        // Results
        optimizedDescription: '✨ Tu Descripción de Producto Optimizada',

        // Stats
        descriptionsGenerated: 'Descripciones Generadas',
        happyCustomers: 'Clientes Satisfechos',
        timesSaved: 'Horas Ahorradas',

        // Notifications
        descriptionCopied: '¡Descripción copiada al portapapeles!',
        usageDataRefreshed: 'Datos de uso actualizados',

        // Language Switcher
        selectLanguage: 'Idioma',

        // Support Footer
        supportText: '¿Necesitas ayuda? Contacta a nuestro equipo de soporte',

        // Language Options
        languageOptionEnglish: 'Inglés',
        languageOptionSpanish: 'Español',
        languageOptionFrench: 'Francés',
        languageOptionGerman: 'Alemán',
        languageOptionItalian: 'Italiano',
        languageOptionPortugueseBR: 'Portugués (Brasil)',
        languageOptionDutch: 'Holandés',
        languageOptionJapanese: 'Japonés',
        languageOptionChinese: 'Chino',
        languageOptionRussian: 'Ruso',
        languageOptionArabic: 'Árabe',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Coreano'
    },

    fr: {
        // Header
        pageTitle: 'SolTecSol - Générateur de Descriptions de Produits IA',
        companyName: 'SolTecSol (Solutions Technologiques Solides)',
        appTitle: 'Générateur de Descriptions IA',
        subscriptionPlans: 'Plans d\'Abonnement',
        createAccount: 'Créer un Compte',
        signIn: 'Se Connecter',
        tagline: 'Transformez les URLs de Produits en Textes qui Convertissent',
        subtitle: 'Générez des descriptions de produits optimisées SEO et spécifiques à la marque qui convertissent les visiteurs en acheteurs. Économisez des heures de rédaction et augmentez vos ventes e-commerce.',

        // Generator Section
        generateSection: 'Générez Votre Description',
        monthlyUsage: 'Usage Mensuel',
        usedDescriptions: 'descriptions utilisées',
        freeDescriptions: 'descriptions gratuites utilisées',
        of: 'de',
        unlimitedDescriptions: 'illimitées',
        usageCounterText: '{{used}} de {{total}} descriptions gratuites utilisées',
        upgradePrompt: 'Mettre à niveau pour des descriptions illimitées →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Confiance des Leaders E-commerce',
        averageSalesIncrease: 'Augmentation Moyenne des Ventes',
        averageTimeSaved: 'Temps Moyen Économisé',
        customerSatisfaction: 'Satisfaction Client',

        // Input Mode Buttons
        productURL: '🔗 URL du Produit',
        barcodeUPC: '📊 Code-barres/UPC',
        manualEntry: '✏️ Saisie Manuelle',

        // Form Labels
        productIdentification: 'Identification du Produit',
        productUrl: 'URL du Produit',
        productUrlPlaceholder: 'https://exemple.com/page-produit',
        barcodeNumber: 'Numéro de Code-barres/UPC',
        barcodePlaceholder: 'Entrez le code-barres ou numéro UPC',
        lookupProduct: '🔍 Rechercher Produit',
        productName: 'Nom du Produit',
        productNamePlaceholder: 'Entrez le nom du produit',
        brand: 'Marque',
        brandPlaceholder: 'Entrez le nom de la marque',
        category: 'Catégorie',
        categoryPlaceholder: 'ex., Électronique, Vêtements',
        brandTone: 'Ton de Marque',
        descriptionLength: 'Longueur de Description',
        language: 'Langue',
        targetAudience: 'Public Cible (Optionnel)',
        targetAudiencePlaceholder: 'ex., parents occupés, passionnés de fitness, professionnels de la tech',
        keyFeatures: 'Caractéristiques Clés à Mettre en Avant (Optionnel)',
        keyFeaturesPlaceholder: 'Listez les caractéristiques les plus importantes que vous souhaitez souligner...',

        // Brand Tone Options
        selectBrandVoice: 'Sélectionnez votre voix de marque...',
        luxuryPremium: 'Luxe et Premium',
        casualFriendly: 'Décontracté et Amical',
        professionalAuthoritative: 'Professionnel et Autoritaire',
        funQuirky: 'Amusant et Excentrique',
        minimalistClean: 'Minimaliste et Épuré',

        // Length Options
        shortLength: 'Courte (50-100 mots) - Rapide et Percutante',
        mediumLength: 'Moyenne (150-250 mots) - Recommandée',
        extensiveLength: 'Longue (300-500 mots) - Détaillée',

        // Buttons
        generateDescription: 'Générer Description IA',
        copyToClipboard: '📋 Copier dans le Presse-papiers',

        // Results
        optimizedDescription: '✨ Votre Description de Produit Optimisée',

        // Stats
        descriptionsGenerated: 'Descriptions Générées',
        happyCustomers: 'Clients Satisfaits',
        timesSaved: 'Heures Économisées',

        // Notifications
        descriptionCopied: 'Description copiée dans le presse-papiers !',
        usageDataRefreshed: 'Données d\'usage actualisées',

        // Language Switcher
        selectLanguage: 'Langue',

        // Support Footer
        supportText: 'Besoin d\'aide ? Contactez notre équipe de support',

        // Language Options
        languageOptionEnglish: 'Anglais',
        languageOptionSpanish: 'Espagnol',
        languageOptionFrench: 'Français',
        languageOptionGerman: 'Allemand',
        languageOptionItalian: 'Italien',
        languageOptionPortugueseBR: 'Portugais (Brésil)',
        languageOptionDutch: 'Néerlandais',
        languageOptionJapanese: 'Japonais',
        languageOptionChinese: 'Chinois',
        languageOptionRussian: 'Russe',
        languageOptionArabic: 'Arabe',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Coréen'
    },

    de: {
        // Header
        pageTitle: 'SolTecSol - KI Produktbeschreibungs-Generator',
        companyName: 'SolTecSol (Solide Technische Lösungen)',
        appTitle: 'KI Produktbeschreibungs-Generator',
        subscriptionPlans: 'Abonnementpläne',
        createAccount: 'Konto Erstellen',
        signIn: 'Anmelden',
        tagline: 'Produkt-URLs in verkaufsfördernde Texte verwandeln',
        subtitle: 'Erstellen Sie SEO-optimierte, markenspezifische Produktbeschreibungen, die Besucher in Käufer verwandeln. Sparen Sie Stunden beim Schreiben und steigern Sie Ihre E-Commerce-Verkäufe.',

        // Generator Section
        generateSection: '🚀 Erstellen Sie Ihre Produktbeschreibung',
        monthlyUsage: 'Monatliche Nutzung',
        usedDescriptions: 'verwendete Produktbeschreibungen',
        freeDescriptions: 'kostenlose Produktbeschreibungen verwendet',
        of: 'von',
        unlimitedDescriptions: 'unbegrenzte Produktbeschreibungen',
        usageCounterText: '{{used}} von {{total}} kostenlosen Beschreibungen verwendet',
        upgradePrompt: 'Upgrade für unbegrenzte Produktbeschreibungen →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Vertrauen von E-Commerce-Führern',
        averageSalesIncrease: 'Durchschnittliche Umsatzsteigerung',
        averageTimeSaved: 'Durchschnittlich gesparte Zeit',
        customerSatisfaction: 'Kundenzufriedenheit',

        // Input Mode Buttons
        productURL: '🔗 Produkt-URL',
        barcodeUPC: '📊 Barcode/UPC',
        manualEntry: '✏️ Manuelle Eingabe',

        // Form Labels
        productIdentification: 'Produktidentifikation',
        productUrl: 'Produkt-URL',
        productUrlPlaceholder: 'https://beispiel.com/produkt-seite',
        barcodeNumber: 'Barcode/UPC Nummer',
        barcodePlaceholder: 'Barcode oder UPC Nummer eingeben',
        lookupProduct: '🔍 Produkt Suchen',
        productName: 'Produktname',
        productNamePlaceholder: 'Produktname eingeben',
        brand: 'Marke',
        brandPlaceholder: 'Markenname eingeben',
        category: 'Kategorie',
        categoryPlaceholder: 'z.B., Elektronik, Bekleidung',
        brandTone: 'Markenton',
        descriptionLength: 'Beschreibungslänge',
        language: 'Sprache',
        targetAudience: 'Zielgruppe (Optional)',
        targetAudiencePlaceholder: 'z.B. beschäftigte Eltern, Fitness-Enthusiasten, Tech-Profis',
        keyFeatures: 'Wichtigste Eigenschaften (Optional)',
        keyFeaturesPlaceholder: 'Listen Sie die wichtigsten Eigenschaften auf, die Sie betonen möchten...',

        // Brand Tone Options
        selectBrandVoice: 'Wählen Sie Ihren Markenton...',
        luxuryPremium: 'Luxuriös & Premium',
        casualFriendly: 'Lässig & Freundlich',
        professionalAuthoritative: 'Professionell & Kompetent',
        funQuirky: 'Verspielt & Eigenwillig',
        minimalistClean: 'Minimalistisch & Sauber',

        // Length Options
        shortLength: 'Kurz (50-100 Wörter) - Knapp & Prägnant',
        mediumLength: 'Mittel (150-250 Wörter) - Empfohlen',
        extensiveLength: 'Ausführlich (300-500 Wörter) - Detailliert',

        // Buttons
        generateDescription: 'KI-Produktbeschreibung generieren',
        copyToClipboard: '📋 In Zwischenablage kopieren',

        // Results
        optimizedDescription: '✨ Ihre optimierte Produktbeschreibung',

        // Stats
        descriptionsGenerated: 'Beschreibungen Generiert',
        happyCustomers: 'Zufriedene Kunden',
        timesSaved: 'Gesparte Stunden',

        // Notifications
        descriptionCopied: 'Beschreibung in die Zwischenablage kopiert!',
        usageDataRefreshed: 'Nutzungsdaten aktualisiert',

        // Language Switcher
        selectLanguage: 'Sprache',

        // Support Footer
        supportText: 'Brauchen Sie Hilfe? Kontaktieren Sie unser Support-Team',

        // Language Options
        languageOptionEnglish: 'Englisch',
        languageOptionSpanish: 'Spanisch',
        languageOptionFrench: 'Französisch',
        languageOptionGerman: 'Deutsch',
        languageOptionItalian: 'Italienisch',
        languageOptionPortugueseBR: 'Portugiesisch (Brasilien)',
        languageOptionDutch: 'Niederländisch',
        languageOptionJapanese: 'Japanisch',
        languageOptionChinese: 'Chinesisch',
        languageOptionRussian: 'Russisch',
        languageOptionArabic: 'Arabisch',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Koreanisch'
    },

    it: {
        // Header
        pageTitle: 'SolTecSol - Generatore di Descrizioni Prodotto AI',
        companyName: 'SolTecSol (Soluzioni Tecnologiche Solide)',
        appTitle: 'Generatore di Descrizioni AI',
        subscriptionPlans: 'Piani di Abbonamento',
        createAccount: 'Crea Account',
        signIn: 'Accedi',
        tagline: 'Trasforma gli URL dei Prodotti in Testi che Convertono',
        subtitle: 'Genera descrizioni di prodotti ottimizzate SEO e specifiche del marchio che convertono i visitatori in acquirenti. Risparmia ore di scrittura e aumenta le vendite e-commerce.',

        // Generator Section
        generateSection: ' Genera la Tua Descrizione',
        monthlyUsage: 'Uso Mensile',
        usedDescriptions: 'descrizioni utilizzate',
        freeDescriptions: 'descrizioni gratuite utilizzate',
        of: 'di',
        unlimitedDescriptions: 'illimitate',
        usageCounterText: '{{used}} di {{total}} descrizioni gratuite utilizzate',
        upgradePrompt: 'Aggiorna per descrizioni illimitate →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Fiducia dei Leader E-commerce',
        averageSalesIncrease: 'Aumento Medio delle Vendite',
        averageTimeSaved: 'Tempo Medio Risparmiato',
        customerSatisfaction: 'Soddisfazione del Cliente',

        // Input Mode Buttons
        productURL: '🔗 URL del Prodotto',
        barcodeUPC: '📊 Codice a Barre/UPC',
        manualEntry: '✏️ Inserimento Manuale',

        // Form Labels
        productIdentification: 'Identificazione del Prodotto',
        productUrl: 'URL del Prodotto',
        productUrlPlaceholder: 'https://esempio.com/pagina-prodotto',
        barcodeNumber: 'Numero Codice a Barre/UPC',
        barcodePlaceholder: 'Inserisci codice a barre o numero UPC',
        lookupProduct: '🔍 Cerca Prodotto',
        productName: 'Nome del Prodotto',
        productNamePlaceholder: 'Inserisci nome del prodotto',
        brand: 'Marca',
        brandPlaceholder: 'Inserisci nome della marca',
        category: 'Categoria',
        categoryPlaceholder: 'es. Elettronica, Abbigliamento',
        brandTone: 'Tono della Marca',
        descriptionLength: 'Lunghezza Descrizione',
        language: 'Lingua',
        targetAudience: 'Pubblico Target (Opzionale)',
        targetAudiencePlaceholder: 'es. genitori impegnati, appassionati di fitness, professionisti tech',
        keyFeatures: 'Caratteristiche Chiave da Evidenziare (Opzionale)',
        keyFeaturesPlaceholder: 'Elenca le caratteristiche più importanti che vuoi enfatizzare...',

        // Brand Tone Options
        selectBrandVoice: 'Seleziona la voce del tuo brand...',
        luxuryPremium: 'Lusso e Premium',
        casualFriendly: 'Casual e Amichevole',
        professionalAuthoritative: 'Professionale e Autorevole',
        funQuirky: 'Divertente e Stravagante',
        minimalistClean: 'Minimalista e Pulito',

        // Length Options
        shortLength: 'Corta (50-100 parole) - Veloce e Diretta',
        mediumLength: 'Media (150-250 parole) - Consigliata',
        extensiveLength: 'Estesa (300-500 parole) - Dettagliata',

        // Buttons
        generateDescription: 'Genera Descrizione AI',
        copyToClipboard: '📋 Copia negli Appunti',

        // Results
        optimizedDescription: '✨ La Tua Descrizione Prodotto Ottimizzata',

        // Stats
        descriptionsGenerated: 'Descrizioni Generate',
        happyCustomers: 'Clienti Soddisfatti',
        timesSaved: 'Ore Risparmiate',

        // Notifications
        descriptionCopied: 'Descrizione copiata negli appunti!',
        usageDataRefreshed: 'Dati di utilizzo aggiornati',

        // Language Switcher
        selectLanguage: 'Lingua',

        // Support Footer
        supportText: 'Hai bisogno di aiuto? Contatta il nostro team di supporto',

        // Language Options
        languageOptionEnglish: 'Inglese',
        languageOptionSpanish: 'Spagnolo',
        languageOptionFrench: 'Francese',
        languageOptionGerman: 'Tedesco',
        languageOptionItalian: 'Italiano',
        languageOptionPortugueseBR: 'Portoghese (Brasile)',
        languageOptionDutch: 'Olandese',
        languageOptionJapanese: 'Giapponese',
        languageOptionChinese: 'Cinese',
        languageOptionRussian: 'Russo',
        languageOptionArabic: 'Arabo',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Coreano'
    },

    'pt-BR': {
        // Header
        pageTitle: 'SolTecSol - Gerador de Descrições de Produtos com IA',
        companyName: 'SolTecSol (Soluções Tecnológicas Sólidas)',
        appTitle: 'Gerador de Descrições com IA',
        subscriptionPlans: 'Planos de Assinatura',
        createAccount: 'Criar Conta',
        signIn: 'Entrar',
        tagline: 'Transforme URLs de Produtos em Textos que Convertem',
        subtitle: 'Gere descrições de produtos otimizadas para SEO e específicas da marca que convertem navegadores em compradores. Economize horas de tempo de escrita e impulsione suas vendas de e-commerce.',

        // Generator Section
        generateSection: 'Gere Sua Descrição',
        monthlyUsage: 'Uso Mensal',
        usedDescriptions: 'descrições usadas',
        freeDescriptions: 'descrições gratuitas usadas',
        of: 'de',
        unlimitedDescriptions: 'ilimitadas',
        usageCounterText: '{{used}} de {{total}} descrições gratuitas usadas',
        upgradePrompt: 'Faça upgrade para descrições ilimitadas →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Confiança de Líderes do E-commerce',
        averageSalesIncrease: 'Aumento Médio de Vendas',
        averageTimeSaved: 'Tempo Médio Economizado',
        customerSatisfaction: 'Satisfação do Cliente',

        // Input Mode Buttons
        productURL: '🔗 URL do Produto',
        barcodeUPC: '📊 Código de Barras/UPC',
        manualEntry: '✏️ Entrada Manual',

        // Form Labels
        productIdentification: 'Identificação do Produto',
        productUrl: 'URL do Produto',
        productUrlPlaceholder: 'https://exemplo.com/pagina-produto',
        barcodeNumber: 'Número do Código de Barras/UPC',
        barcodePlaceholder: 'Digite o código de barras ou número UPC',
        lookupProduct: '🔍 Buscar Produto',
        productName: 'Nome do Produto',
        productNamePlaceholder: 'Digite o nome do produto',
        brand: 'Marca',
        brandPlaceholder: 'Digite o nome da marca',
        category: 'Categoria',
        categoryPlaceholder: 'ex.: Eletrônicos, Roupas',
        brandTone: 'Tom da Marca',
        descriptionLength: 'Comprimento da Descrição',
        language: 'Idioma',
        targetAudience: 'Público-alvo (Opcional)',
        targetAudiencePlaceholder: 'ex.: pais ocupados, entusiastas de fitness, profissionais de tecnologia',
        keyFeatures: 'Recursos Principais a Destacar (Opcional)',
        keyFeaturesPlaceholder: 'Liste os recursos mais importantes que você deseja enfatizar...',

        // Brand Tone Options
        selectBrandVoice: 'Selecione a voz da sua marca...',
        luxuryPremium: 'Luxo e Premium',
        casualFriendly: 'Casual e Amigável',
        professionalAuthoritative: 'Profissional e Autoritativo',
        funQuirky: 'Divertido e Peculiar',
        minimalistClean: 'Minimalista e Limpo',

        // Length Options
        shortLength: 'Curta (50-100 palavras) - Rápida e Direta',
        mediumLength: 'Média (150-250 palavras) - Recomendada',
        extensiveLength: 'Extensa (300-500 palavras) - Detalhada',

        // Buttons
        generateDescription: 'Gerar Descrição com IA',
        copyToClipboard: '📋 Copiar para Área de Transferência',

        // Results
        optimizedDescription: '✨ Sua Descrição de Produto Otimizada',

        // Stats
        descriptionsGenerated: 'Descrições Geradas',
        happyCustomers: 'Clientes Satisfeitos',
        timesSaved: 'Horas Economizadas',

        // Notifications
        descriptionCopied: 'Descrição copiada para a área de transferência!',
        usageDataRefreshed: 'Dados de uso atualizados',

        // Language Switcher
        selectLanguage: 'Idioma',

        // Support Footer
        supportText: 'Precisa de ajuda? Entre em contato com nossa equipe de suporte',

        // Language Options
        languageOptionEnglish: 'Inglês',
        languageOptionSpanish: 'Espanhol',
        languageOptionFrench: 'Francês',
        languageOptionGerman: 'Alemão',
        languageOptionItalian: 'Italiano',
        languageOptionPortugueseBR: 'Português (Brasil)',
        languageOptionDutch: 'Holandês',
        languageOptionJapanese: 'Japonês',
        languageOptionChinese: 'Chinês',
        languageOptionRussian: 'Russo',
        languageOptionArabic: 'Árabe',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Coreano'
    },

    nl: {
        // Header
        pageTitle: 'SolTecSol - AI Productbeschrijving Generator',
        companyName: 'SolTecSol (Solide Technische Oplossingen)',
        appTitle: 'AI Beschrijving Generator',
        subscriptionPlans: 'Abonnementsplannen',
        createAccount: 'Account Aanmaken',
        signIn: 'Inloggen',
        tagline: 'Product URLs omzetten naar Converterende Tekst',
        subtitle: 'Genereer SEO-geoptimaliseerde, merkspecifieke productbeschrijvingen die bezoekers omzetten naar kopers. Bespaar uren schrijftijd en verhoog je e-commerce verkopen.',

        // Generator Section
        generateSection: 'Genereer Uw Beschrijving',
        monthlyUsage: 'Maandelijks Gebruik',
        usedDescriptions: 'beschrijvingen gebruikt',
        freeDescriptions: 'gratis beschrijvingen gebruikt',
        of: 'van',
        unlimitedDescriptions: 'onbeperkt',
        usageCounterText: '{{used}} van {{total}} gratis beschrijvingen gebruikt',
        upgradePrompt: 'Upgrade voor onbeperkte beschrijvingen →',
        statNumber1: '10K+',
        statNumber2: '250%',
        statNumber3: '45-60min',
        statNumber4: '98%',
        trustedByLeaders: '🎯 Vertrouwd door E-commerce Leiders',
        averageSalesIncrease: 'Gemiddelde Verkoop Toename',
        averageTimeSaved: 'Gemiddeld Bespaarde Tijd',
        customerSatisfaction: 'Klant Tevredenheid',

        // Input Mode Buttons
        productURL: '🔗 Product URL',
        barcodeUPC: '📊 Barcode/UPC',
        manualEntry: '✏️ Handmatige Invoer',

        // Form Labels
        productIdentification: 'Product Identificatie',
        productUrl: 'Product URL',
        productUrlPlaceholder: 'https://voorbeeld.com/product-pagina',
        barcodeNumber: 'Barcode/UPC Nummer',
        barcodePlaceholder: 'Voer barcode of UPC nummer in',
        lookupProduct: '🔍 Product Opzoeken',
        productName: 'Productnaam',
        productNamePlaceholder: 'Voer productnaam in',
        brand: 'Merk',
        brandPlaceholder: 'Voer merknaam in',
        category: 'Categorie',
        categoryPlaceholder: 'bijv. Elektronica, Kleding',
        brandTone: 'Merktoon',
        descriptionLength: 'Beschrijvingslengte',
        language: 'Taal',
        targetAudience: 'Doelgroep (Optioneel)',
        targetAudiencePlaceholder: 'bijv. drukke ouders, fitness-enthousiastelingen, tech-professionals',
        keyFeatures: 'Belangrijkste Kenmerken om te Benadrukken (Optioneel)',
        keyFeaturesPlaceholder: 'Lijst de belangrijkste kenmerken die u wilt benadrukken...',

        // Brand Tone Options
        selectBrandVoice: 'Selecteer uw merkstem...',
        luxuryPremium: 'Luxe & Premium',
        casualFriendly: 'Casual & Vriendelijk',
        professionalAuthoritative: 'Professioneel & Gezaghebbend',
        funQuirky: 'Leuk & Eigenzinnig',
        minimalistClean: 'Minimalistisch & Schoon',

        // Length Options
        shortLength: 'Kort (50-100 woorden) - Snel & Krachtig',
        mediumLength: 'Gemiddeld (150-250 woorden) - Aanbevolen',
        extensiveLength: 'Uitgebreid (300-500 woorden) - Gedetailleerd',

        // Buttons
        generateDescription: 'AI Beschrijving Genereren',
        copyToClipboard: '📋 Kopiëren naar Klembord',

        // Results
        optimizedDescription: '✨ Uw Geoptimaliseerde Productbeschrijving',

        // Stats
        descriptionsGenerated: 'Beschrijvingen Gegenereerd',
        happyCustomers: 'Tevreden Klanten',
        timesSaved: 'Uren Bespaard',

        // Notifications
        descriptionCopied: 'Beschrijving gekopieerd naar klembord!',
        usageDataRefreshed: 'Gebruiksgegevens bijgewerkt',

        // Language Switcher
        selectLanguage: 'Taal',

        // Support Footer
        supportText: 'Hulp nodig? Neem contact op met ons ondersteuningsteam',

        // Language Options
        languageOptionEnglish: 'Engels',
        languageOptionSpanish: 'Spaans',
        languageOptionFrench: 'Frans',
        languageOptionGerman: 'Duits',
        languageOptionItalian: 'Italiaans',
        languageOptionPortugueseBR: 'Portugees (Brazilië)',
        languageOptionDutch: 'Nederlands',
        languageOptionJapanese: 'Japans',
        languageOptionChinese: 'Chinees',
        languageOptionRussian: 'Russisch',
        languageOptionArabic: 'Arabisch',
        languageOptionHindi: 'Hindi',
        languageOptionKorean: 'Koreaans'
    },

    ja: {
        // Header
        pageTitle: 'SolTecSol - AI商品説明ジェネレーター',
        companyName: 'SolTecSol (ソリッドテック ソリューションズ)',
        appTitle: 'AI説明ジェネレーター',
        subscriptionPlans: 'サブスクリプションプラン',
        createAccount: 'アカウント作成',
        signIn: 'サインイン',
        tagline: '商品URLを売れる文章に変換',
        subtitle: 'SEO最適化されたブランド特有の商品説明を生成し、訪問者を購入者に変換します。執筆時間を節約し、Eコマースの売上を向上させましょう。',

        // Generator Section
        generateSection: '説明を生成',
        monthlyUsage: '月間使用量',
        usedDescriptions: '説明使用済み',
        freeDescriptions: '無料説明使用済み',
        of: 'の',
        unlimitedDescriptions: '無制限',
        usageCounterText: '{{used}}/{{total}} 無料説明を使用中',
        upgradePrompt: '無制限説明にアップグレード →',
        statNumber1: '一万+',
        statNumber2: '二百五十%',
        statNumber3: '四十五-六十分',
        statNumber4: '九十八%',
        trustedByLeaders: '🎯 Eコマースリーダーからの信頼',
        averageSalesIncrease: '平均売上増加',
        averageTimeSaved: '平均時間短縮',
        customerSatisfaction: '顧客満足度',

        // Input Mode Buttons
        productURL: '🔗 商品URL',
        barcodeUPC: '📊 バーコード/UPC',
        manualEntry: '✏️ 手動入力',

        // Form Labels
        productIdentification: '商品識別',
        productUrl: '商品URL',
        productUrlPlaceholder: 'https://例.サイト/商品ページ',
        barcodeNumber: 'バーコード/UPC番号',
        barcodePlaceholder: 'バーコードまたはUPC番号を入力',
        lookupProduct: '🔍 商品検索',
        productName: '商品名',
        productNamePlaceholder: '商品名を入力',
        brand: 'ブランド',
        brandPlaceholder: 'ブランド名を入力',
        category: 'カテゴリー',
        categoryPlaceholder: '例：電化製品、衣類',
        brandTone: 'ブランドトーン',
        descriptionLength: '説明の長さ',
        language: '言語',
        targetAudience: 'ターゲット層（任意）',
        targetAudiencePlaceholder: '例：忙しい親、フィットネス愛好者、IT専門家',
        keyFeatures: '強調する主要機能（任意）',
        keyFeaturesPlaceholder: '強調したい最も重要な機能をリストアップしてください...',

        // Brand Tone Options
        selectBrandVoice: 'ブランドボイスを選択...',
        luxuryPremium: 'ラグジュアリー・プレミアム',
        casualFriendly: 'カジュアル・フレンドリー',
        professionalAuthoritative: 'プロフェッショナル・権威的',
        funQuirky: 'ファン・個性的',
        minimalistClean: 'ミニマリスト・クリーン',

        // Length Options
        shortLength: '短め（五十〜百語）- 簡潔・インパクト',
        mediumLength: '中程度（百五十～二百五十語）- 推奨',
        extensiveLength: '詳細（三百～五百語）- 詳しく',

        // Buttons
        generateDescription: 'AI説明を生成',
        copyToClipboard: '📋 クリップボードにコピー',

        // Results
        optimizedDescription: '✨ 最適化された商品説明',

        // Stats
        descriptionsGenerated: '生成された説明数',
        happyCustomers: '満足顧客数',
        timesSaved: '節約時間',

        // Notifications
        descriptionCopied: '説明がクリップボードにコピーされました！',
        usageDataRefreshed: '使用データが更新されました',

        // Language Switcher
        selectLanguage: '言語',

        // Support Footer
        supportText: 'サポートが必要ですか？サポートチームにお問い合わせください',

        // Language Options
        languageOptionEnglish: '英語',
        languageOptionSpanish: 'スペイン語',
        languageOptionFrench: 'フランス語',
        languageOptionGerman: 'ドイツ語',
        languageOptionItalian: 'イタリア語',
        languageOptionPortugueseBR: 'ポルトガル語 (ブラジル)',
        languageOptionDutch: 'オランダ語',
        languageOptionJapanese: '日本語',
        languageOptionChinese: '中国語',
        languageOptionRussian: 'ロシア語',
        languageOptionArabic: 'アラビア語',
        languageOptionHindi: 'ヒンディー語',
        languageOptionKorean: '韓国語'

    },

    zh: {
        // Header
        pageTitle: 'SolTecSol - AI产品描述生成器',
        companyName: 'SolTecSol (固体科技解决方案)',
        appTitle: 'AI描述生成器',
        subscriptionPlans: '订阅计划',
        createAccount: '创建账户',
        signIn: '登录',
        tagline: '将产品URL转换为转化文案',
        subtitle: '生成SEO优化的品牌特定产品描述，将访客转化为买家。节省数小时写作时间，提升电商销售。',

        // Generator Section
        generateSection: '生成您的描述',
        monthlyUsage: '月度使用量',
        usedDescriptions: '已使用描述',
        freeDescriptions: '已使用免费描述',
        of: '的',
        unlimitedDescriptions: '无限制',
        usageCounterText: '已使用{{used}}/{{total}}个免费描述',
        upgradePrompt: '升级获得无限描述 →',
        statNumber1: '一万+',
        statNumber2: '二百五十%',
        statNumber3: '四十五-六十分钟',
        statNumber4: '九十八%',
        trustedByLeaders: '🎯 电商领导者信赖',
        averageSalesIncrease: '平均销售增长',
        averageTimeSaved: '平均节省时间',
        customerSatisfaction: '客户满意度',

        // Input Mode Buttons
        productURL: '🔗 产品URL',
        barcodeUPC: '📊 条形码/UPC',
        manualEntry: '✏️ 手动输入',

        // Form Labels
        productIdentification: '产品识别',
        productUrl: '产品URL',
        productUrlPlaceholder: 'https://示例.网站/产品页面',
        barcodeNumber: '条形码/UPC号码',
        barcodePlaceholder: '输入条形码或UPC号码',
        lookupProduct: '🔍 查找产品',
        productName: '产品名称',
        productNamePlaceholder: '输入产品名称',
        brand: '品牌',
        brandPlaceholder: '输入品牌名称',
        category: '类别',
        categoryPlaceholder: '例如：电子产品，服装',
        brandTone: '品牌语调',
        descriptionLength: '描述长度',
        language: '语言',
        targetAudience: '目标受众（可选）',
        targetAudiencePlaceholder: '例如：忙碌的父母，健身爱好者，技术专业人士',
        keyFeatures: '要突出的关键特性（可选）',
        keyFeaturesPlaceholder: '列出您想要强调的最重要特性...',

        // Brand Tone Options
        selectBrandVoice: '选择您的品牌声音...',
        luxuryPremium: '奢华高端',
        casualFriendly: '休闲友好',
        professionalAuthoritative: '专业权威',
        funQuirky: '有趣独特',
        minimalistClean: '简约干净',

        // Length Options
        shortLength: '简短（五十至一百字）- 快速有力',
        mediumLength: '中等（一百五十至二百五十字）- 推荐',
        extensiveLength: '详细（三百至五百字）- 详尽',

        // Buttons
        generateDescription: '生成AI描述',
        copyToClipboard: '📋 复制到剪贴板',

        // Results
        optimizedDescription: '✨ 您的优化产品描述',

        // Stats
        descriptionsGenerated: '生成的描述数',
        happyCustomers: '满意客户',
        timesSaved: '节省小时数',

        // Notifications
        descriptionCopied: '描述已复制到剪贴板！',
        usageDataRefreshed: '使用数据已刷新',

        // Language Switcher
        selectLanguage: '语言',

        // Support Footer
        supportText: '需要帮助吗？联系我们的支持团队',

        // Language Options
        languageOptionEnglish: '英语',
        languageOptionSpanish: '西班牙语',
        languageOptionFrench: '法语',
        languageOptionGerman: '德语',
        languageOptionItalian: '意大利语',
        languageOptionPortugueseBR: '葡萄牙语 (巴西)',
        languageOptionDutch: '荷兰语',
        languageOptionJapanese: '日语',
        languageOptionChinese: '中文',
        languageOptionRussian: '俄语',
        languageOptionArabic: '阿拉伯语',
        languageOptionHindi: '印地语',
        languageOptionKorean: '韩语'

    },

    ru: {
        // Header
        pageTitle: 'SolTecSol - AI Генератор Описаний Товаров',
        companyName: 'SolTecSol (Надёжные Технические Решения)',
        appTitle: 'AI Генератор Описаний',
        subscriptionPlans: 'Планы Подписки',
        createAccount: 'Создать Аккаунт',
        signIn: 'Войти',
        tagline: 'Превратите URL товаров в продающие тексты',
        subtitle: 'Создавайте SEO-оптимизированные, брендовые описания товаров, которые превращают посетителей в покупателей. Экономьте часы на написании и увеличивайте продажи интернет-магазина.',

        // Generator Section
        generateSection: 'Создать Описание',
        monthlyUsage: 'Месячное Использование',
        usedDescriptions: 'описаний использовано',
        freeDescriptions: 'бесплатных описаний использовано',
        of: 'из',
        unlimitedDescriptions: 'неограничено',
        usageCounterText: '{{used}} из {{total}} бесплатных описаний использовано',
        upgradePrompt: 'Обновить до неограниченных описаний →',
        statNumber1: 'десять тыс.+',
        statNumber2: 'двести пятьдесят%',
        statNumber3: 'сорок пять-шестьдесят мин',
        statNumber4: 'девяносто восемь%',
        trustedByLeaders: '🎯 Доверие лидеров э-коммерции',
        averageSalesIncrease: 'Средний рост продаж',
        averageTimeSaved: 'Среднее сэкономленное время',
        customerSatisfaction: 'Удовлетворенность клиентов',

        // Input Mode Buttons
        productURL: '🔗 URL Товара',
        barcodeUPC: '📊 Штрихкод/UPC',
        manualEntry: '✏️ Ручной Ввод',

        // Form Labels
        productIdentification: 'Идентификация Товара',
        productUrl: 'URL Товара',
        productUrlPlaceholder: 'https://пример.com/страница-товара',
        barcodeNumber: 'Номер Штрихкода/UPC',
        barcodePlaceholder: 'Введите штрихкод или номер UPC',
        lookupProduct: '🔍 Найти Товар',
        productName: 'Название Товара',
        productNamePlaceholder: 'Введите название товара',
        brand: 'Бренд',
        brandPlaceholder: 'Введите название бренда',
        category: 'Категория',
        categoryPlaceholder: 'например: Электроника, Одежда',
        brandTone: 'Тон Бренда',
        descriptionLength: 'Длина Описания',
        language: 'Язык',
        targetAudience: 'Целевая Аудитория (Необязательно)',
        targetAudiencePlaceholder: 'например: занятые родители, фитнес-энтузиасты, IT-специалисты',
        keyFeatures: 'Ключевые Особенности для Выделения (Необязательно)',
        keyFeaturesPlaceholder: 'Перечислите наиболее важные особенности, которые вы хотите подчеркнуть...',

        // Brand Tone Options
        selectBrandVoice: 'Выберите голос вашего бренда...',
        luxuryPremium: 'Люкс и Премиум',
        casualFriendly: 'Непринужденный и Дружелюбный',
        professionalAuthoritative: 'Профессиональный и Авторитетный',
        funQuirky: 'Веселый и Необычный',
        minimalistClean: 'Минималистичный и Чистый',

        // Length Options
        shortLength: 'Короткое (пятьдесят-сто слов) - Быстро и Ёмко',
        mediumLength: 'Среднее (сто пятьдесят-двести пятьдесят слов) - Рекомендуется',
        extensiveLength: 'Развернутое (триста-пятьсот слов) - Подробно',

        // Buttons
        generateDescription: 'Создать AI Описание',
        copyToClipboard: '📋 Копировать в Буфер',

        // Results
        optimizedDescription: '✨ Ваше Оптимизированное Описание Товара',

        // Stats
        descriptionsGenerated: 'Создано Описаний',
        happyCustomers: 'Довольных Клиентов',
        timesSaved: 'Сэкономлено Часов',

        // Notifications
        descriptionCopied: 'Описание скопировано в буфер обмена!',
        usageDataRefreshed: 'Данные использования обновлены',

        // Language Switcher
        selectLanguage: 'Язык',

        // Support Footer
        supportText: 'Нужна помощь? Свяжитесь с нашей службой поддержки',

        // Language Options
        languageOptionEnglish: 'Английский',
        languageOptionSpanish: 'Испанский',
        languageOptionFrench: 'Французский',
        languageOptionGerman: 'Немецкий',
        languageOptionItalian: 'Итальянский',
        languageOptionPortugueseBR: 'Португальский (Бразилия)',
        languageOptionDutch: 'Голландский',
        languageOptionJapanese: 'Японский',
        languageOptionChinese: 'Китайский',
        languageOptionRussian: 'Русский',
        languageOptionArabic: 'Арабский',
        languageOptionHindi: 'Хинди',
        languageOptionKorean: 'Корейский'

    },

    ar: {
        // Header
        pageTitle: 'SolTecSol - مولد وصف المنتجات بالذكاء الاصطناعي',
        companyName: 'SolTecSol (حلول تقنية صلبة)',
        appTitle: 'مولد الوصف بالذكاء الاصطناعي',
        subscriptionPlans: 'خطط الاشتراك',
        createAccount: 'إنشاء حساب',
        signIn: 'تسجيل الدخول',
        tagline: 'حول عناوين المنتجات إلى نصوص تسويقية',
        subtitle: 'أنتج أوصاف منتجات محسنة لمحركات البحث وخاصة بالعلامة التجارية تحول الزوار إلى مشترين. وفر ساعات من الكتابة وزد مبيعات التجارة الإلكترونية.',

        // Generator Section
        generateSection: 'أنتج وصفك',
        monthlyUsage: 'الاستخدام الشهري',
        usedDescriptions: 'الأوصاف المستخدمة',
        freeDescriptions: 'الأوصاف المجانية المستخدمة',
        of: 'من',
        unlimitedDescriptions: 'غير محدود',
        usageCounterText: '{{used}} من {{total}} أوصاف مجانية مستخدمة',
        upgradePrompt: 'ترقية للأوصاف غير المحدودة ←',
        statNumber1: 'عشرة آلاف+',
        statNumber2: 'مائتان وخمسون%',
        statNumber3: 'خمسة وأربعون-ستون دقيقة',
        statNumber4: 'ثمانية وتسعون%',
        trustedByLeaders: '🎯 ثقة قادة التجارة الإلكترونية',
        averageSalesIncrease: 'متوسط زيادة المبيعات',
        averageTimeSaved: 'متوسط الوقت الموفر',
        customerSatisfaction: 'رضا العملاء',

        // Input Mode Buttons
        productURL: '🔗 رابط المنتج',
        barcodeUPC: '📊 رمز شريطي/UPC',
        manualEntry: '✏️ إدخال يدوي',

        // Form Labels
        productIdentification: 'تحديد المنتج',
        productUrl: 'رابط المنتج',
        productUrlPlaceholder: 'https://مثال.موقع/صفحة-المنتج',
        barcodeNumber: 'رقم الرمز الشريطي/UPC',
        barcodePlaceholder: 'أدخل الرمز الشريطي أو رقم UPC',
        lookupProduct: '🔍 بحث عن المنتج',
        productName: 'اسم المنتج',
        productNamePlaceholder: 'أدخل اسم المنتج',
        brand: 'العلامة التجارية',
        brandPlaceholder: 'أدخل اسم العلامة التجارية',
        category: 'الفئة',
        categoryPlaceholder: 'مثال: إلكترونيات، ملابس',
        brandTone: 'نبرة العلامة التجارية',
        descriptionLength: 'طول الوصف',
        language: 'اللغة',
        targetAudience: 'الجمهور المستهدف (اختياري)',
        targetAudiencePlaceholder: 'مثال: الآباء المشغولون، محبي اللياقة، محترفي التكنولوجيا',
        keyFeatures: 'الميزات الرئيسية للتأكيد عليها (اختياري)',
        keyFeaturesPlaceholder: 'قم بإدراج أهم الميزات التي تريد التأكيد عليها...',

        // Brand Tone Options
        selectBrandVoice: 'اختر صوت علامتك التجارية...',
        luxuryPremium: 'فاخر ومميز',
        casualFriendly: 'بسيط وودي',
        professionalAuthoritative: 'مهني وموثق',
        funQuirky: 'ممتع وفريد',
        minimalistClean: 'بسيط ونظيف',

        // Length Options
        shortLength: 'قصير (خمسون-مائة كلمة) - سريع ومؤثر',
        mediumLength: 'متوسط (مائة وخمسون-مائتان وخمسون كلمة) - موصى',
        extensiveLength: 'مفصل (ثلاثمائة-خمسمائة كلمة) - شامل',

        // Buttons
        generateDescription: 'إنتاج وصف بالذكاء الاصطناعي',
        copyToClipboard: '📋 نسخ إلى الحافظة',

        // Results
        optimizedDescription: '✨ وصف المنتج المحسن',

        // Stats
        descriptionsGenerated: 'أوصاف منتجة',
        happyCustomers: 'عملاء سعداء',
        timesSaved: 'ساعات موفرة',

        // Notifications
        descriptionCopied: 'تم نسخ الوصف إلى الحافظة!',
        usageDataRefreshed: 'تم تحديث بيانات الاستخدام',

        // Language Switcher
        selectLanguage: 'اللغة',

        // Support Footer
        supportText: 'تحتاج مساعدة؟ تواصل مع فريق الدعم',

        // Language Options
        languageOptionEnglish: 'الإنجليزية',
        languageOptionSpanish: 'الإسبانية',
        languageOptionFrench: 'الفرنسية',
        languageOptionGerman: 'الألمانية',
        languageOptionItalian: 'الإيطالية',
        languageOptionPortugueseBR: 'البرتغالية (البرازيل)',
        languageOptionDutch: 'الهولندية',
        languageOptionJapanese: 'اليابانية',
        languageOptionChinese: 'الصينية',
        languageOptionRussian: 'الروسية',
        languageOptionArabic: 'العربية',
        languageOptionHindi: 'الهندية',
        languageOptionKorean: 'الكورية'

    },

    hi: {
        // Header
        pageTitle: 'SolTecSol - AI उत्पाद विवरण जेनरेटर',
        companyName: 'SolTecSol (ठोस तकनीकी समाधान)',
        appTitle: 'AI विवरण जेनरेटर',
        subscriptionPlans: 'सब्सक्रिप्शन योजनाएं',
        createAccount: 'खाता बनाएं',
        signIn: 'साइन इन',
        tagline: 'उत्पाद URLs को बिकने वाली सामग्री में बदलें',
        subtitle: 'SEO-अनुकूलित, ब्रांड-विशिष्ट उत्पाद विवरण बनाएं जो आगंतुकों को खरीदारों में बदल देते हैं। लेखन समय की घंटों की बचत करें और अपनी ई-कॉमर्स बिक्री बढ़ाएं।',

        // Generator Section
        generateSection: 'अपना विवरण बनाएं',
        monthlyUsage: 'मासिक उपयोग',
        usedDescriptions: 'विवरण उपयोग किए गए',
        freeDescriptions: 'मुफ्त विवरण उपयोग किए गए',
        of: 'का',
        unlimitedDescriptions: 'असीमित',
        usageCounterText: '{{used}} का {{total}} मुफ्त विवरण उपयोग किए गए',
        upgradePrompt: 'असीमित विवरण के लिए अपग्रेड करें →',
        statNumber1: 'दस हज़ार+',
        statNumber2: 'ढाई सौ%',
        statNumber3: 'पैंतालीस-साठ मिनट',
        statNumber4: 'अट्ठानवे%',
        trustedByLeaders: '🎯 ई-कॉमर्स नेताओं द्वारा भरोसा',
        averageSalesIncrease: 'औसत बिक्री वृद्धि',
        averageTimeSaved: 'औसत समय बचत',
        customerSatisfaction: 'ग्राहक संतुष्टि',

        // Input Mode Buttons
        productURL: '🔗 उत्पाद URL',
        barcodeUPC: '📊 बारकोड/UPC',
        manualEntry: '✏️ मैनुअल एंट्री',

        // Form Labels
        productIdentification: 'उत्पाद पहचान',
        productUrl: 'उत्पाद URL',
        productUrlPlaceholder: 'https://उदाहरण.साइट/उत्पाद-पेज',
        barcodeNumber: 'बारकोड/UPC नंबर',
        barcodePlaceholder: 'बारकोड या UPC नंबर दर्ज करें',
        lookupProduct: '🔍 उत्पाद खोजें',
        productName: 'उत्पाद का नाम',
        productNamePlaceholder: 'उत्पाद का नाम दर्ज करें',
        brand: 'ब्रांड',
        brandPlaceholder: 'ब्रांड का नाम दर्ज करें',
        category: 'श्रेणी',
        categoryPlaceholder: 'जैसे: इलेक्ट्रॉनिक्स, कपड़े',
        brandTone: 'ब्रांड टोन',
        descriptionLength: 'विवरण की लंबाई',
        language: 'भाषा',
        targetAudience: 'लक्षित दर्शक (वैकल्पिक)',
        targetAudiencePlaceholder: 'जैसे: व्यस्त माता-पिता, फिटनेस उत्साही, तकनीकी पेशेवर',
        keyFeatures: 'हाइलाइट करने के लिए मुख्य विशेषताएं (वैकल्पिक)',
        keyFeaturesPlaceholder: 'वे सबसे महत्वपूर्ण विशेषताएं लिस्ट करें जिन्हें आप एम्फेसाइज करना चाहते हैं...',

        // Brand Tone Options
        selectBrandVoice: 'अपने ब्रांड वॉइस का चयन करें...',
        luxuryPremium: 'लक्जरी और प्रीमियम',
        casualFriendly: 'कैजुअल और मित्रवत',
        professionalAuthoritative: 'प्रोफेशनल और अथॉरिटेटिव',
        funQuirky: 'मजेदार और क्विर्की',
        minimalistClean: 'मिनिमलिस्ट और क्लीन',

        // Length Options
        shortLength: 'संक्षिप्त (पचास-सौ शब्द) - तेज और पंची',
        mediumLength: 'मध्यम (डेढ़ सौ-ढाई सौ पचास शब्द) - सुझाव',
        extensiveLength: 'विस्तृत (तीन सौ-पाँच सौ शब्द) - विस्तार',

        // Buttons
        generateDescription: 'AI विवरण जेनरेट करें',
        copyToClipboard: '📋 क्लिपबोर्ड में कॉपी करें',

        // Results
        optimizedDescription: '✨ आपका अनुकूलित उत्पाद विवरण',

        // Stats
        descriptionsGenerated: 'जेनरेट किए गए विवरण',
        happyCustomers: 'खुश ग्राहक',
        timesSaved: 'बचाए गए घंटे',

        // Notifications
        descriptionCopied: 'विवरण क्लिपबोर्ड में कॉपी कर दिया गया!',
        usageDataRefreshed: 'उपयोग डेटा रिफ्रेश किया गया',

        // Language Switcher
        selectLanguage: 'भाषा',

        // Support Footer
        supportText: 'मदद चाहिए? हमारी सपोर्ट टीम से संपर्क करें',

        // Language Options
        languageOptionEnglish: 'अंग्रेजी',
        languageOptionSpanish: 'स्पेनिश',
        languageOptionFrench: 'फ्रेंच',
        languageOptionGerman: 'जर्मन',
        languageOptionItalian: 'इतालवी',
        languageOptionPortugueseBR: 'पुर्तगाली (ब्राजील)',
        languageOptionDutch: 'डच',
        languageOptionJapanese: 'जापानी',
        languageOptionChinese: 'चीनी',
        languageOptionRussian: 'रूसी',
        languageOptionArabic: 'अरबी',
        languageOptionHindi: 'हिंदी',
        languageOptionKorean: 'कोरियाई'

    },

    ko: {
        // Header
        pageTitle: 'SolTecSol - AI 제품 설명 생성기',
        companyName: 'SolTecSol (견고한 기술 솔루션)',
        appTitle: 'AI 설명 생성기',
        subscriptionPlans: '구독 요금제',
        createAccount: '계정 만들기',
        signIn: '로그인',
        tagline: '제품 URL을 전환하는 카피로 변환',
        subtitle: 'SEO 최적화된 브랜드별 제품 설명을 생성하여 방문자를 구매자로 전환하세요. 작성 시간을 절약하고 전자상거래 판매를 증대하세요.',

        // Generator Section
        generateSection: '설명 생성하기',
        monthlyUsage: '월간 사용량',
        usedDescriptions: '사용된 설명',
        freeDescriptions: '사용된 무료 설명',
        of: '의',
        unlimitedDescriptions: '무제한',
        usageCounterText: '{{used}}/{{total}} 무료 설명 사용됨',
        upgradePrompt: '무제한 설명으로 업그레이드 →',
        statNumber1: '만+',
        statNumber2: '이백오십%',
        statNumber3: '사십오-육십분',
        statNumber4: '구십팔%',
        trustedByLeaders: '🎯 전자상거래 리더들의 신뢰',
        averageSalesIncrease: '평균 매출 증가',
        averageTimeSaved: '평균 시간 절약',
        customerSatisfaction: '고객 만족도',

        // Input Mode Buttons
        productURL: '🔗 제품 URL',
        barcodeUPC: '📊 바코드/UPC',
        manualEntry: '✏️ 수동 입력',

        // Form Labels
        productIdentification: '제품 식별',
        productUrl: '제품 URL',
        productUrlPlaceholder: 'https://예시.사이트/제품-페이지',
        barcodeNumber: '바코드/UPC 번호',
        barcodePlaceholder: '바코드 또는 UPC 번호를 입력하세요',
        lookupProduct: '🔍 제품 검색',
        productName: '제품명',
        productNamePlaceholder: '제품명을 입력하세요',
        brand: '브랜드',
        brandPlaceholder: '브랜드명을 입력하세요',
        category: '카테고리',
        categoryPlaceholder: '예: 전자제품, 의류',
        brandTone: '브랜드 톤',
        descriptionLength: '설명 길이',
        language: '언어',
        targetAudience: '타겟 고객층 (선택사항)',
        targetAudiencePlaceholder: '예: 바쁜 부모, 피트니스 애호가, 기술 전문가',
        keyFeatures: '강조할 주요 기능 (선택사항)',
        keyFeaturesPlaceholder: '강조하고 싶은 가장 중요한 기능들을 나열하세요...',

        // Brand Tone Options
        selectBrandVoice: '브랜드 보이스를 선택하세요...',
        luxuryPremium: '럭셔리 & 프리미엄',
        casualFriendly: '캐주얼 & 친근한',
        professionalAuthoritative: '전문적 & 권위있는',
        funQuirky: '재미있고 & 독특한',
        minimalistClean: '미니멀 & 깔끔한',

        // Length Options
        shortLength: '짧은 설명 (쉰단어-백단어) - 빠르고 강력한',
        mediumLength: '보통 설명 (백쉰단어-이백쉰단어) - 추천',
        extensiveLength: '자세한 설명 (삼백단어-오백단어) - 상세한',

        // Buttons
        generateDescription: 'AI 설명 생성',
        copyToClipboard: '📋 클립보드에 복사',

        // Results
        optimizedDescription: '✨ 최적화된 제품 설명',

        // Stats
        descriptionsGenerated: '생성된 설명 수',
        happyCustomers: '만족한 고객 수',
        timesSaved: '절약한 시간',

        // Notifications
        descriptionCopied: '설명이 클립보드에 복사되었습니다!',
        usageDataRefreshed: '사용량 데이터가 새로고쳐졌습니다',

        // Language Switcher
        selectLanguage: '언어',

        // Support Footer
        supportText: '도움이 필요하신가요? 지원팀에 문의해 주세요',

        // Language Options
        languageOptionEnglish: '영어',
        languageOptionSpanish: '스페인어',
        languageOptionFrench: '프랑스어',
        languageOptionGerman: '독일어',
        languageOptionItalian: '이탈리아어',
        languageOptionPortugueseBR: '포르투갈어 (브라질)',
        languageOptionDutch: '네덜란드어',
        languageOptionJapanese: '일본어',
        languageOptionChinese: '중국어',
        languageOptionRussian: '러시아어',
        languageOptionArabic: '아랍어',
        languageOptionHindi: '힌디어',
        languageOptionKorean: '한국어'

    }
};

// Translation utility function
function t(key) {
    const lang = window.currentLanguage || 'en';
    if (translations[lang] && translations[lang][key]) {
        return translations[lang][key];
    }
    return key;
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { translations, t };
}

// Export for ES6 modules
if (typeof window !== 'undefined') {
    window.translations = translations;
    window.t = t;
}