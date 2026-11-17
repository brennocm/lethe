# Recuperação após crash

O lethe falha fechado. Se o daemon morre com a guarda `strict` ou em pânico, as tabelas nftables `lethe*` ficam, e **a rede continua bloqueada**. Isso é de propósito: um crash nunca pode virar um vazamento. Nada aqui fica escondido do operador; os passos abaixo devolvem a rede.

## 1. Entender o estado

Abra o painel do lethe. Ele diz, em qualquer caso, se a rede está bloqueada, por quê e como sair:

- **Daemon de pé, sem sessão** (o systemd o reiniciou depois da queda): o quadro de bloqueio lista as tabelas que sobraram. Iniciar sessão fica recusado até a rede ser liberada, para que a sessão nova não esconda o bloqueio antigo.
- **Daemon parado** (modo portátil, ou serviço desligado): o painel diz "O lethe não está rodando" e mostra **Liberar a rede** ao lado de **Iniciar o lethe**.

No terminal: `sudo lethe status`. Sem daemon, ele lista as tabelas que sobraram e diz como sair.

## 2. Liberar a rede

| Situação | No painel | No terminal |
|---|---|---|
| Sessão em PÂNICO, túnel de volta | Reconheça os CRITICAL e clique em **Sair do pânico** | `lethe ack ID --reason "..."`, depois `lethe unpanic` |
| Sessão em PÂNICO, o túnel não volta | **Encerrar sessão** (passphrase): encerra, remove as tabelas e religa as interfaces | `lethe disarm` |
| Daemon morto, ou reiniciado sem sessão | **Liberar a rede** (o sistema pede a senha de administrador) | `sudo lethe cleanup` |
| Daemon de pé, não responde | — | `sudo lethe cleanup` |
| Nem o `lethe` roda | — | reinicie a máquina: as tabelas nftables não sobrevivem ao boot |

- **Liberar a rede** sobe `lethe-cleanup.service`, que roda `lethe cleanup` como root, só com `CAP_NET_ADMIN`. O painel só diz que liberou depois de o systemd confirmar que o cleanup terminou bem.
- `cleanup` remove **só** as tabelas cujo nome começa com `lethe` e lista cada uma que removeu. Rodado sem nada a remover, diz que o lethe não está bloqueando a rede.
- Nada fora de `storage.dir` e de `$XDG_RUNTIME_DIR/lethe` (ou `/run/lethe`) é criado, então não há mais nada para limpar.

## 3. Conferir a sessão interrompida

```
lethe verify DIR_DA_SESSAO --baseline BASELINE --expect-fingerprint XXXX-...
```

Uma sessão que caiu não tem relatório em **Relatórios** (ele é gerado ao encerrar); o painel diz como gerá-lo com `lethe report`.

Depois de um crash, o esperado é passar, com avisos:

- `truncated_tail`: o último registro foi gravado pela metade. Os anteriores estão íntegros;
- `session did not end cleanly`: não há `session.end`;
- `missing_trailer`: o crash foi ao fechar o último segmento;
- `events after the last signature`: os eventos estão encadeados, mas os últimos não chegaram a ser assinados.

Exit 4 é outra coisa: **alteração** no log. Não apague nada; preserve a pasta e escale.

## 4. Descobrir o motivo

- **Modo portátil:** a saída do `run` no terminal.
- **Modo serviço:** `journalctl -u lethed@$USER` (ou `-u lethed`, na configuração à mão).
  - `signal=SYS` é o seccomp; colete o que falta como descrito em `service-mode.md`.
  - `signal=KILL` sem pedido seu: confira o OOM no `journalctl -k`.
- Antes de voltar a operar, rode um selftest completo na mesma máquina.
