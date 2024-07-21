// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config



import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Writeups',
  tagline: 'Dinosaurs are cool',
  favicon: 'img/0_medium.png',

  // Set the production url of your site here
  url: 'https://writeups-kunull.vercel.app/',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'Kunull', // Usually your GitHub org/user name.
  projectName: 'Write-ups', // Usually your repo name.

  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'ignore',

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          breadcrumbs: false,
          sidebarPath: './sidebars.js',
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'dark',
        disableSwitch: true,
        respectPrefersColorScheme: false,
      },
      
      // Replace with your project's social card
      // image: 'img/docusaurus-social-card.jpg',
      navbar: {
        title: 'Writeups',
        logo: {
          alt: 'My Site Logo',
          src: 'img/0_medium.png',
        },

        items: [
          {
            type: 'dropdown',
            label: 'CTF accounts',
            position: 'right',
            items: [
              {
                label: 'TryHackMe',
                href: 'https://tryhackme.com/p/Kunull',
              },
              {
                label: 'Hack The Box',
                href: 'https://app.hackthebox.com/profile/1158503',
              },
              {
                label: 'CyberDefenders',
                href: 'https://cyberdefenders.org/p/Kunull',
              },
              {
                label: 'RootMe',
                href: 'https://www.root-me.org/Kunull?lang=fr#715a5db3518744d717e43af1d56ba448',
              },
            ],
          },

          {
            type: 'dropdown',
            label: 'Other sites',
            position: 'right',
            items: [
              {
                label: 'Blog',
                href: 'https://blog-kunull.vercel.app',
              },
              {
                label: 'Reports',
                href: 'https://reports-kunull.vercel.app',
              },
              {
                label: 'Main site',
                href: 'https://kunull.vercel.app',
              },
            ],
          },

          {
            type: 'dropdown',
            label: 'Socials',
            position: 'right',
            items: [
              {
                label: 'GitHub',
                href: 'https://github.com/kunull',
              },
              {
                label: 'LinkedIn',
                href: 'https://www.linkedin.com/in/kunull/',
              },  
            ],
          },

          {
            type: 'dropdown',
            label: 'Contact',
            position: 'right',
            items: [
              {
                label: 'Email',
                href: 'mailto:llunuk@protonmail.com',
              },
            ],
          }, 
        ],
      },
      // footer: {
      //   style: 'light',
      //   links: [
      //     {
      //       title: 'Other collections',
      //       items: [
      //         {
      //           label: 'Blog',
      //           href: 'https://kunalwalavalkarblog.vercel.app',
      //         },
      //       ],
      //     },
          
      //     {
      //       title: 'Socials',
      //       items: [
      //         {
      //           label: 'Main site',
      //           href: 'https://kunalwalavalkar.vercel.app',
      //         },
      //         {
      //           label: 'Github',
      //           href: 'https://github.com/KuNull',
      //         },
      //         {
      //           href: 'https://www.linkedin.com/in/kunalwalavalkar/',
      //           label: 'LinkedIn',
      //         },
      //       ],
      //     },

      //     {
      //       title: 'CTF Accounts',
      //       items: [
      //         {
      //           label: 'TryHackMe',
      //           href: 'https://tryhackme.com/p/KuNull',
      //         },
      //         {
      //           label: 'Hack The Box',
      //           href: 'https://app.hackthebox.com/profile/1158503',
      //         },
      //       ],
      //     },
          
      //   ],
      //   copyright: `Copyright © ${new Date().getFullYear()} Kunal Walavalkar.`,
      // },
      prism: {
        theme: prismThemes.oneDark,
      },
      algolia: {
          // The application ID provided by Algolia
        appId: 'PKV0V904II',
          // Public API key: it is safe to commit it
        apiKey: 'd05053bf471ae2fdb9bae6a79e013a90',
        indexName: 'writeups-kunull',
        // contextualSearch: false,
        typoTolerance: false,
        maxResultsPerGroup: 9999,
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 5,
      },
    }),
  
};

export default config;
