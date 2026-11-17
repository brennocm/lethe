# Recuperação após crash

O lethe falha fechado. Se o daemon morre com a guarda `strict` ou em pânico, as tabelas nftables `lethe*` ficam, e **a rede continua bloqueada**. Isso é de propósito: um crash nunca pode virar um vazamento. Nada aqui fica escondido do operador; os passos abaixo devolvem a rede.

## 1. Entender o estado

```
sudo lethe status
```

Sem daemon, ele lista as tabelas que sobraram e diz como sair. Se o daemon estiver de pé, mostra a sessão e o bloqueio.

## 2. Liberar a rede

| Situação | Comando |
|---|---|
| Daemon de pé, em PÂNICO | `lethe ack ID --reason "..."` para cada CRITICAL, depois `lethe unpanic` |
| Daemon de pé, não responde | `sudo lethe cleanup` |
| Daemon morto (crash, `kill -9`, OOM, seccomp) | `sudo lethe cleanup` |
| Nem o `lethe` roda | reinicie a máquina: as tabelas nftables não sobrevivem ao boot |

- `cleanup` remove **só** as tabelas cujo nome começa com `lethe` e lista cada uma que removeu. Rodado sem nada a remover, diz que o lethe não está bloqueando a rede.
- Nada fora de `storage.dir` e de `$XDG_RUNTIME_DIR/lethe` (ou `/run/lethe`) é criado, então não há mais nada para limpar.

## 3. Conferir a sessão interrompida

```
lethe verify DIR_DA_SESSAO --baseline BASELINE --expect-fingerprint XXXX-...
```

Depois de um crash, o esperado é passar, com avisos:

- `truncated_tail`: o último registro foi gravado pela metade. Os anteriores estão íntegros;
- `session did not end cleanly`: não há `session.end`;
- `missing_trailer`: o crash foi ao fechar o último segmento;
- `events after the last signature`: os eventos estão encadeados, mas os últimos não chegaram a ser assinados.

Exit 4 é outra coisa: **alteração** no log. Não apague nada; preserve a pasta e escale.

## 4. Descobrir o motivo

- **Modo portátil:** a saída do `run` no terminal.
- **Modo serviço:** `journalctl -u lethed`.
  - `signal=SYS` é o seccomp; colete o que falta como descrito em `service-mode.md`.
  - `signal=KILL` sem pedido seu: confira o OOM no `journalctl -k`.
- Antes de voltar a operar, rode um selftest completo na mesma máquina.
