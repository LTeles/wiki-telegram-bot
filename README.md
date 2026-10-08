# TelesGramBot — ptwiki

Monitora mudanças recentes da Wikipédia em português, envia alertas ao Telegram
e mantém relatórios controlados nas subpáginas de `Usuário:TelesGramBot/`.

## Lista de alto risco com espera de duas horas

A versão 3.36 substitui a publicação na TestWiki por uma fila persistente para a
ptwiki. Uma revisão com Revert Risk estritamente superior a 80% é registrada com
o horário original da edição e só fica elegível duas horas depois.

Na revalidação, o alerta é suprimido quando houver evidência de:

- patrulhamento manual da revisão no registro da ptwiki (autopatrulha não conta);
- reversão, autorreversão, eliminação ou resolução já registrada pelo bot;
- tag `mw-reverted` na revisão;
- restauração exata da revisão anterior ou alteração posterior que torne o
  conteúdo sinalizado obsoleto.

Quando uma alteração posterior é ambígua, a decisão é adiada por 15 minutos em
vez de publicar. A mesma revalidação é repetida imediatamente antes da escrita.

O MediaWiki não oferece ao bot um sinal confiável de mera visualização humana.
Por isso, “vista pela comunidade” é implementado pelo evento auditável de
patrulhamento manual, além dos desfechos objetivos acima.

## Modos de operação

`PTWIKI_HIGH_RISK_MODE` aceita:

- `off`: não cria candidatos;
- `shadow`: padrão seguro; cria e revalida a fila, mas não escreve a lista;
- `publish`: habilita as páginas de alto risco na fila única de escrita da
  ptwiki.

O estado fica em `/data/ptwiki_high_risk_candidates_v1.json` (ou no diretório
indicado por `TOOL_DATA_DIR`). A ativação em produção deve ocorrer somente depois
de validar o volume persistente, as credenciais/direitos da conta bot, as páginas
de destino e os resultados do modo `shadow`.

O histórico legado da TestWiki pode continuar no arquivo local para aprendizado,
mas não é elegível para publicação na ptwiki sem a marca gerada pela nova
revalidação. Da mesma forma, decisões concluídas em `shadow` não são reproduzidas
retroativamente quando o modo muda para `publish`; somente novos candidatos
seguem o fluxo publicável.

Os comandos existentes permanecem disponíveis. `/pausarteste` e
`/reiniciarteste` são aliases legados que agora pausam ou retomam somente a lista
de alto risco da ptwiki; `/pausarwiki` e `/reiniciarwiki` controlam toda a escrita
automatizada na ptwiki.

## Verificação local

```text
python -m py_compile bot.py
python -m unittest -v test_high_risk_delay.py
```
