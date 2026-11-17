# Operação

Roteiro de uma operação no modo portátil. O modo serviço está em `service-mode.md`.

## Antes (uma vez por máquina e por identidade)

1. Confira o binário: `lethe version` deve mostrar o SHA-256 das notas da release.
2. Na rede real, **sem** VPN, crie:
   - a baseline: `lethe baseline create`;
   - o perfil: `lethe profile init --out op.yaml`, depois edite-o e rode `lethe profile validate op.yaml`.

   `lethe setup` faz os dois perguntando.
3. Guarde a passphrase da baseline **fora** da máquina. Sem ela não há reconhecimento de alerta CRITICAL, nem `unpanic`, nem `disarm`.
4. Primeira vez: `sudo lethe run -p op.yaml --guard off`, depois `lethe selftest` noutro terminal. Só passe para `strict` depois de um selftest completo aprovado.

## Começo da operação

1. Ligue a VPN (ou o Tor).
2. Rode `sudo lethe run -p op.yaml`:
   - o preflight roda primeiro; se der FAIL, nada é aplicado e a saída diz o que corrigir (exit 2);
   - no estrito, o lethe espera até `guard.arm_confirm` o túnel passar tráfego; se não passar, desfaz tudo (exit 6) e explica.
3. **Anote fora da máquina a impressão digital** da chave de sessão que aparece em seguida. O `verify` usa essa anotação depois.
4. A GUI (ou a TUI, com `--tui`) mostra o estado: VERDE ok, AMARELO aviso, VERMELHO crítico, CINZA sensor parado.

## Durante

| Sinal | O que fazer |
|---|---|
| AMARELO (WARNING) | Leia o "o que fazer" do alerta. `lethe ack ID` reconhece sem passphrase |
| VERMELHO (CRITICAL), tela cheia | **Pare de usar a identidade.** Leia a causa. Corrija, ou acione o pânico se não souber o motivo. Reconheça com motivo e passphrase (`lethe ack ID --reason "..."`) |
| CINZA | Um sensor parou: o lethe não está vendo aquela parte. Trate como risco até voltar |
| PÂNICO | A rede está bloqueada de propósito. Reconheça os CRITICAL, corrija a causa e rode `lethe unpanic`, que confere túnel, rotas e IPv6 antes de liberar |

- `lethe status` mostra tudo a qualquer momento, inclusive o bloqueio ativo, o porquê e como sair.
- `lethe panic` bloqueia na hora, sem passphrase.

## Fim

1. Encerre com Ctrl-C no `run`, ou com `lethe disarm` noutro terminal (este pede a passphrase). As tabelas saem e o log é fechado e assinado.
2. Se a sessão terminou em PÂNICO, o bloqueio **continua** de propósito. `sudo lethe cleanup` libera.
3. Exit 3 significa que a sessão teve CRITICAL. Verifique e gere o relatório (`session-verification.md`).
4. Desligue a VPN só depois do disarm.

Se algo travar, ou se o daemon morrer, siga `crash-recovery.md`.
