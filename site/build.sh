#!/bin/bash
# Génère index.html (page autonome servie par waitlist/server.py) à partir de presentation.html.
# presentation.html reste la source (aussi publiée en aperçu, sans formulaire actif).
set -e
cd "$(dirname "$0")"
{
  printf '<!doctype html>\n<html lang="fr-BE">\n<head>\n<meta charset="utf-8">\n'
  printf '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
  printf '<script>window.WAITLIST_ENDPOINT = "/api/inscription";</script>\n'
  cat presentation.html
  printf '\n</html>\n'
} > index.html
echo "index.html généré"
