# Verificação de sessão e retenção

Cada sessão fica em `storage.dir/sessions/<id>/`: segmentos cifrados (age), encadeados por hash e assinados com a chave da sessão, cuja impressão digital você anotou fora da máquina no arm.

## Verificar

```
lethe verify DIR --baseline BASELINE --expect-fingerprint XXXX-XXXX-...
```

- **Exit 0:** cadeia, checkpoints e assinaturas íntegros, e a chave é a que você anotou. Avisos depois de um crash estão em `crash-recovery.md`.
- **Exit 4:** um byte alterado ou um segmento trocado. A saída aponta o segmento e o `seq`. Preserve tudo e escale.
- **Sem `--expect-fingerprint`:** o `verify` só prova coerência interna. Quem trocou a sessão inteira por outra, assinada com outra chave, passaria. Use sempre a anotação.
- No lugar de `--baseline`, `--identity ARQUIVO` abre o log com uma identidade age separada.

## Relatório

Ao encerrar a sessão, o daemon verifica o log e grava `report.md` na pasta da sessão (quando o log não é cifrado para chaves institucionais). O painel o mostra em **Relatórios** (no formulário de início), sem passphrase e sem terminal. Para o caso, gere-o de novo com a impressão digital que você anotou:

```
lethe report DIR --baseline BASELINE --expect-fingerprint ... [--format json]
```

- O relatório verifica antes de gerar. Com o log alterado, ele não gera nada e sai com 4.
- Ele lista alertas, reconhecimentos com motivo, respostas executadas, pânicos e o resultado do selftest.
- Valores da baseline nunca aparecem: os casamentos aparecem pelo nome do campo.
- Campos sensíveis (IPs de saída, por exemplo) só aparecem com `--include-sensitive` e a identidade que os abre. Gere essa versão só quando a política do caso exigir, e trate o arquivo como dado do caso.

## Retenção (spec D6)

O lethe **nunca apaga sessões**: a retenção é política da instituição. Recomendações:

- copie a pasta da sessão e o relatório para o repositório de evidências do caso, com a anotação da impressão digital;
- confira o `verify` na cópia antes de apagar o original;
- apague só seguindo a política escrita, registrando quem apagou e quando;
- a baseline e a passphrase vivem mais que as sessões: sem elas, os logs antigos não abrem.
