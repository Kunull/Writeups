// @ts-check
// `@type` JSDoc annotations allow editor autocompletion and type checking
// (when paired with `@ts-check`).
// There are various equivalent ways to declare your Docusaurus config.
// See: https://docusaurus.io/docs/api/docusaurus-config



import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Write-ups',
  tagline: 'Dinosaurs are cool',
  favicon: 'img/play.png',

  // Set the production url of your site here
  url: 'https://github.com',
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: '/Write-ups',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'facebook', // Usually your GitHub org/user name.
  projectName: 'Write-ups | Knign', // Usually your repo name.

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
          sidebarPath: './sidebars.js',
          routeBasePath: '/',
        },
        blog: {
          showReadingTime: true,
        },
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
        title: 'Write-ups | Knign',
        logo: {
          alt: 'My Site Logo',
          src: 'img/play.png',
        },
        items: [
          {
            href: 'https://kunalwalavalkarblog.vercel.app',
            label: 'Blog',
            position: 'left',
          },
          
          {
            href: 'https://kunalwalavalkar.vercel.app',
            label: 'Main site',
            position: 'right',
          },
          {
            href: 'https://github.com/Knign',
            label: 'GitHub',
            position: 'right',
          },
          {
            href: 'https://www.linkedin.com/in/kunalwalavalkar/',
            label: 'LinkedIn',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'light',
        links: [
          {
            title: 'Other collections',
            items: [
              {
                label: 'Blog',
                href: 'https://kunalwalavalkarblog.vercel.app',
              },
            ],
          },
          
          {
            title: 'Socials',
            items: [
              {
                label: 'Main site',
                href: 'https://kunalwalavalkar.vercel.app',
              },
              {
                label: 'Github',
                href: 'https://github.com/Knign',
              },
              {
                href: 'https://www.linkedin.com/in/kunalwalavalkar/',
                label: 'LinkedIn',
              },
            ],
          },

          {
            title: 'CTF Accounts',
            items: [
              {
                label: 'TryHackMe',
                href: 'https://tryhackme.com/p/Knign',
              },
              {
                label: 'Hack The Box',
                href: 'https://app.hackthebox.com/profile/1158503',
              },
            ],
          },
          
        ],
        copyright: `Copyright © ${new Date().getFullYear()} Kunal Walavalkar.`,
      },
      prism: {
        theme: prismThemes.vsDark,
      },

      
    }),
  
};

export default config;
