# Mon Maillon — consignes pour Claude

## Le produit
Appli web (PWA) pour familles belges francophones : les parents envoient une capture
(mail d'école, mot du club…) ou transfèrent un e-mail ; l'IA propose des événements,
tâches, paiements et choses à apporter ; le parent valide ; les tâches sont réparties
entre les deux parents. Aussi : activités des enfants, repas de la semaine.
Principe absolu : l'IA propose, le parent valide.

## Stack
- Next.js (App Router, TypeScript strict), Tailwind, déployé sur Vercel (région fra1)
- Supabase (Postgres, Auth lien magique, Storage, Edge Functions) région eu-central-1
- IA : Mistral via un adaptateur `lib/ai/provider.ts` (interface `extract()`), modèle par variable d'env
- E-mails : Brevo (transactionnel) ; e-mails entrants : Mailgun EU
- Paiement : Stripe Billing
- Tests : Vitest (unitaires), Playwright (E2E) ; CI GitHub Actions

## Règles
- Langue de l'interface : français (Belgique). Dates au format « mar. 12 janv. », fuseau Europe/Brussels.
- RLS activée sur toutes les tables ; jamais la clé service_role côté client.
- Les images uploadées sont supprimées après extraction. Aucun contenu personnel dans les logs.
- Minimiser les données envoyées à l'IA (image/texte + date de réception + prénoms).
- Valider toute sortie IA avec Zod. Prévoir l'échec gracieux.
- Accessibilité : contrastes AA, boutons ≥ 44 px, utilisable d'une main sur mobile.
- Couleurs : bleu nuit #1B1F3B, corail #E8603C, vert d'eau #0F6E66.
- Toujours : écrire/mettre à jour les tests, lancer `npm run test` et `npm run lint` avant de dire « fini ».
- Petites étapes, commits fréquents, messages de commit en français.

## Décisions
