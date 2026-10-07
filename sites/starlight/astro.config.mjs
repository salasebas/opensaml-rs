// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { rewriteDocLinks } from './src/plugins/doc-links.js';

/** Registers the link rewriter on Astro's default Markdown processor. */
function docLinks() {
	return {
		name: 'saml-doc-links',
		hooks: {
			'astro:config:setup'({ config }) {
				config.markdown.processor?.options?.mdastPlugins?.push(rewriteDocLinks());
			},
		},
	};
}

// https://astro.build/config
export default defineConfig({
	integrations: [
		starlight({
			title: 'saml-rs',
			description: 'SAML 2.0 browser SSO, metadata, and Single Logout for Rust.',
			favicon: '/favicon.svg',
			customCss: ['./src/styles/custom.css'],
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/salasebas/saml-rs' }],
			sidebar: [
				{
					label: 'Start',
					items: [
						{ label: 'Install', slug: 'start/install' },
						{ label: 'Run the example', slug: 'tutorial/run-the-sso-example' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Service provider', slug: 'guides/service-provider-sso' },
						{ label: 'Identity provider', slug: 'guides/identity-provider-sso' },
						{ label: 'Single Logout', slug: 'guides/single-logout' },
						{ label: 'Crypto provider', slug: 'guides/crypto-provider' },
						{ label: 'Validation', slug: 'guides/validation-preset' },
						{ label: 'Raw API', slug: 'guides/raw-compatibility' },
						{
							label: 'Upgrade',
							items: [
								{ label: 'Overview', slug: 'guides/upgrade' },
								{ label: '0.2 to 0.3', slug: 'guides/upgrade/v0-2-to-v0-3' },
								{ label: '0.3 to 0.4', slug: 'guides/upgrade/v0-3-to-v0-4' },
								{ label: '0.4 to 0.5', slug: 'guides/upgrade/v0-4-to-v0-5' },
								{ label: '0.5 to 0.6', slug: 'guides/upgrade/v0-5-to-v0-6' },
								{ label: '0.6 to 0.7', slug: 'guides/upgrade/v0-6-to-v0-7' },
							],
						},
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Coverage', slug: 'reference/coverage' },
						{ label: 'Cargo features', slug: 'reference/features' },
						{ label: 'Security', slug: 'reference/security' },
						{ label: 'Compatibility crates', slug: 'reference/compatibility-crates' },
						{
							label: 'Conformance',
							items: [
								{ label: 'How to read them', slug: 'reference/conformance' },
								{
									label: 'SSO acceptance',
									slug: 'reference/conformance/web-browser-sso-acceptance',
								},
								{
									label: 'SSO generation',
									slug: 'reference/conformance/web-browser-sso-generation',
								},
								{ label: 'Logout', slug: 'reference/conformance/single-logout' },
								{
									label: 'Identity Provider Discovery',
									slug: 'reference/conformance/identity-provider-discovery',
								},
								{ label: 'Metadata and replay', slug: 'reference/conformance/metadata-and-replay' },
							],
						},
					],
				},
				{
					label: 'Explanation',
					items: [
						{ label: 'Validation presets', slug: 'explanation/validation-presets' },
						{ label: 'Logout expiration', slug: 'explanation/logout-expiration' },
						{ label: 'XML signatures', slug: 'explanation/xml-signature-recommendations' },
						{ label: 'Typed API', slug: 'explanation/typed-api' },
					],
				},
			],
		}),
		docLinks(),
	],
});
