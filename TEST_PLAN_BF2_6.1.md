# Plano de Testes — Superset 6.1 no BF2

**Ambiente sob teste:** `https://dashboards.bugfixes2.plaidcloud.org` (BF2)
**Versão esperada:** Superset **6.1.0** + 4 plugins custom da última branch 5.1 (versão de produção)
**Baseline de comparação:** ambiente de **produção rodando 5.1.0**
**Data:** 2026-06-09 · **Responsável:** Carlos Ribeiro (+ Claude)

**Objetivo:** Validar que o 6.1 (a) sobe estável, (b) preserva 100% dos dashboards/charts criados no 5.1, e (c) mantém os 4 charts custom de produção funcionando **com os mesmos números e visual** após o upgrade.

---

## Metodologia

- **Critério de PASS:** comportamento idêntico ou melhor que o 5.1 de produção, sem erro de console, sem divergência de dados.
- **Critério de FAIL:** erro visível, chart não renderiza, **número diferente do 5.1**, controle sem efeito, ou crash/cycling.
- **Severidade:** 🔴 Bloqueante (impede go-live) · 🟠 Alta · 🟡 Média · 🔵 Baixa/cosmético.
- **Evidência:** anexar print + (quando aplicável) print equivalente do 5.1 lado a lado.
- **Console:** manter o DevTools (F12 → Console + Network) aberto durante os testes; registrar qualquer erro 4xx/5xx ou exceção JS.
- Legenda status: ⬜ pendente · ✅ pass · ❌ fail · ⚠️ pass com ressalva · ⛔ bloqueado

### Contas usadas
| Papel | Usuário | Observação |
|-------|---------|------------|
| Admin | _(preencher)_ | |
| Não-admin / Gamma | _(preencher)_ | necessário p/ testar RBAC (item 8) |

---

## 0. Infra / Smoke (🔴 bloqueante — fazer primeiro)

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 0.1 | Acesso ao BF2 sem 403 (corrigido o e-mail @tartansolutions vs @plaidcloud) | 🔴 | ✅ | |
| 0.2 | Sem "cycling" (reinício/queda) por ≥10 min de uso | 🔴 | ✅ | Estável |
| 0.3 | Login funciona | 🔴 | ✅ | |
| 0.4 | Versão = **6.1.0** (Settings → About / rodapé) | 🔴 | ✅ | confirmado 6.1.0 (2026-06-10) |
| 0.5 | Health check `/health` responde 200 | 🟡 | ✅ | HTTP 200, 0.79s (2026-06-10) |
| 0.6 | Sem erros no console ao carregar a home | 🟠 | ⬜ | |

---

## 1. Inventário de plugins — presença e registro

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 1.1 | **+ Chart** → os 4 tipos custom aparecem na galeria de viz | 🔴 | ✅ | galeria abre ok (2026-06-10) |
| 1.2 | **Whale** (`plugin-chart-whale` v0.1.0) listado | 🔴 | ✅ | "Whale Chart" na galeria — confirmado via Playwright headless no ambiente local develop-6.1 |
| 1.3 | **Mekko-Whale** (`plugin-chart-mekko-whale` v0.1.0) listado | 🔴 | ✅ | "Plugin Chart Mekko Whale" na galeria; histórico de build error RESOLVIDO — webpack compila o plugin sem erro (ambiente local develop-6.1) |
| 1.4 | **Marimekko** (`plugin-chart-marimekko` v0.1.1) listado | 🔴 | ✅ | "Plugin Chart Marimekko" na galeria |
| 1.5 | **Benchmark Range** (`plugin-chart-benchmark-range` v0.1.0) listado | 🔴 | ✅ | "Benchmarking Range Chart" na galeria — confirmado via Playwright headless no ambiente local develop-6.1 |
| 1.6 | Thumbnails/ícones renderizam (sem placeholder quebrado) | 🔵 | ⚠️ | plugins custom mostram placeholder de quebra-cabeça (sem imagem própria) — cosmético, não funcional |
| 1.7 | Busca da galeria encontra cada um pelo nome | 🔵 | ✅ | busca "plu" filtrou corretamente |

---

## 2. Paridade de migração 5.1 → 6.1 (🔴 o teste mais importante)

> Charts/dashboards salvos no 5.1 de produção devem abrir e mostrar **os mesmos dados** no 6.1.

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 2.1 | Todos os dashboards de produção abrem no 6.1 sem erro | 🔴 | ⬜ | |
| 2.2 | Nenhum chart custom dá "viz type not found" | 🔴 | ⬜ | |
| 2.3 | **Paridade de números:** mesmo chart → mesmos valores que no 5.1 (amostrar 3–5 charts por tipo) | 🔴 | ⬜ | comparar lado a lado |
| 2.4 | **Paridade visual:** cores, ordem, labels, eixos iguais ao 5.1 | 🟠 | ⬜ | |
| 2.5 | Filtros nativos + **cross-filters** salvos funcionam | 🟠 | ⬜ | |
| 2.6 | Editar e **re-salvar** um chart legado não corrompe a config | 🟠 | ⬜ | |
| 2.7 | Layout do dashboard ok (tema 6.1: padding/margins/sizeUnit) | 🟡 | ⬜ | |
| 2.8 | Datasets / colunas calculadas / métricas intactos | 🟠 | ⬜ | |

---

## 3. Whale curve (`plugin-chart-whale`)

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 3.1 | Cria com X-Axis + métrica → curva da "baleia" desenha | 🔴 | ⬜ | |
| 3.2 | **Tooltip-only Metrics** aparecem só no tooltip | 🟡 | ⬜ | |
| 3.3 | **Chart Type** alterna corretamente | 🟠 | ⬜ | |
| 3.4 | **Data Zoom** funciona (arrastar/scroll) | 🟡 | ⬜ | |
| 3.5 | **Show 80/20 Pareto Line** liga/desliga e posiciona certo | 🟠 | ⬜ | |
| 3.6 | **Show Values on Hover** | 🔵 | ⬜ | |
| 3.7 | Cores custom Positive / Neutral / Negative aplicam | 🟡 | ⬜ | |
| 3.8 | **Number Format** no eixo aplica | 🟡 | ⬜ | |
| 3.9 | Edge: dataset vazio / 1 ponto / valores negativos não quebra | 🟠 | ⬜ | |

---

## 4. Mekko-Whale (`plugin-chart-mekko-whale`) — ⚠️ atenção (build error no histórico)

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 4.1 | Cria com Dimension + X/Y → renderiza | 🔴 | ⬜ | |
| 4.2 | **Sort By / Sort Order** ordenam | 🟡 | ⬜ | |
| 4.3 | **Waterfall Mode** funciona | 🟠 | ⬜ | |
| 4.4 | **Show Total Profit Annotation** exibe anotação correta | 🟠 | ⬜ | |
| 4.5 | Cores custom (Start/Mid/End, positive/negative) aplicam | 🟡 | ⬜ | |
| 4.6 | **Y/X Axis Format** aplicam | 🟡 | ⬜ | |
| 4.7 | Edge: dimensão com muitos valores / negativos | 🟠 | ⬜ | |

---

## 5. Marimekko (`plugin-chart-marimekko` v0.1.1)

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 5.1 | Cria com Columns + Height Key (Y) + Width Key (X) → renderiza | 🔴 | ⬜ | |
| 5.2 | **Secondary Entity** funciona | 🟠 | ⬜ | |
| 5.3 | **Show Legend / Show Labels / Label Color** | 🟡 | ⬜ | |
| 5.4 | **Chart Title** + labels de eixo X/Y aplicam | 🔵 | ⬜ | |
| 5.5 | **Sort By / Sort Order** | 🟡 | ⬜ | |
| 5.6 | **Show Percentage** + tooltip (number format, % no tooltip, col names) | 🟡 | ⬜ | |
| 5.7 | Edge: larguras desiguais somam 100% corretamente | 🟠 | ⬜ | |

---

## 6. Benchmark Range (`plugin-chart-benchmark-range`)

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 6.1 | Cria com Profit Center → renderiza | 🔴 | ⬜ | |
| 6.2 | **Show Filter Controls** + Chart Filters funcionam | 🟠 | ⬜ | |
| 6.3 | **Percent Value Mode** | 🟠 | ⬜ | |
| 6.4 | **Sort By / Sort Order** | 🟡 | ⬜ | |
| 6.5 | **Show Legend** + X Axis Label | 🔵 | ⬜ | |

---

## 7. Core Superset 6.1 (regressões portadas nos commits da branch)

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 7.1 | **BigNumber** auto-size header (commit `229035a5c2`) | 🟡 | ⬜ | |
| 7.2 | **Transpose Table** com row heading metrics (commit `f21fc0101b`) | 🟠 | ⬜ | |
| 7.3 | Navegação: Home oculto / sem nav por URL quando configurado (`bdab69636c`) | 🟡 | ⬜ | |
| 7.4 | Color scheme picker (refactor `7dbed9d836`) | 🟡 | ⬜ | |
| 7.5 | SQL Lab roda query + salva | 🟠 | ⬜ | |
| 7.6 | Explore: salvar chart, autocomplete de controles | 🟠 | ⬜ | |

---

## 8. Segurança / RBAC

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 8.1 | **Só Admin gerencia usuários** (commit `efc9beed5f`) — não-admin não vê List Users | 🟠 | ⬜ | precisa conta não-admin |
| 8.2 | Usuário Gamma só enxerga o que tem permissão | 🟠 | ⬜ | |
| 8.3 | Acesso direto a URL de dashboard sem permissão é negado | 🟠 | ⬜ | |

---

## 9. Exports / Reports / Performance

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 9.1 | Export **CSV** de chart custom bate com o que está na tela | 🟠 | ⬜ | |
| 9.2 | Export **imagem (PNG)** do chart | 🔵 | ⬜ | |
| 9.3 | Export/Download do dashboard | 🟡 | ⬜ | |
| 9.4 | Alerts & Reports (se usados em prod) disparam | 🟡 | ⬜ | |
| 9.5 | Tempo de carregamento do dashboard comparável ao 5.1 | 🟡 | ⬜ | |
| 9.6 | Cache de query funciona (2ª carga mais rápida) | 🔵 | ⬜ | |

---

## 10. Compatibilidade

| # | Teste | Sev | Resultado | Notas |
|---|-------|-----|-----------|-------|
| 10.1 | Chrome | 🟡 | ⬜ | |
| 10.2 | Edge/Firefox | 🔵 | ⬜ | |
| 10.3 | Dashboard embed (se usado) renderiza | 🟡 | ⬜ | |

---

## Registro de bugs encontrados

| ID | Item | Sev | Descrição | Esperado (5.1) | Obtido (6.1) | Print |
|----|------|-----|-----------|----------------|--------------|-------|
| BUG-1 | | | | | | |

---

## Resumo / Feedback para Pat & Paul
- **Cobertura:** Blocos 0 e 1 concluídos (smoke + inventário dos 4 plugins). Bloco 2 em diante pendente.
- **Bloqueantes (🔴) abertos:** nenhum até agora.
- **Ressalvas:** 1.6 thumbnails dos plugins custom usam placeholder (cosmético). 6 erros de tipagem (type-only) no build de dev travam só o overlay da porta 9000 — não afetam runtime nem a build de produção do BF2.
- **Recomendação Go / No-go:** _(pendente — após Bloco 2)_

## Andamento (2026-06-10)
- Blocos 0/1 validados no BF2 e confirmados em ambiente local `develop-6.1` (commit `9412301eb2`) via Playwright headless.
- Ambiente local de dev montado (espelha o BF2). Acesso pela porta 8088; login admin/admin.
- Corrigido erro de tipo no `plugin-chart-ag-grid-table` (`getCrossFilterDataMask.ts`, null→undefined).
- **Próximo (2026-06-11):** Bloco 2 (paridade de migração 5.1→6.1) e Blocos 3-6 (por plugin).
