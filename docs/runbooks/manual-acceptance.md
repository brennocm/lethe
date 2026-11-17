# Teste de aceitação manual (AC-15)

O que o netlab não cobre: Wi-Fi real, NetworkManager, o Tor Browser e a GUI em desktops de verdade. Rode este roteiro antes de cada release, em:

- Debian 12;
- Ubuntu 24.04;
- Fedora (a versão atual).

Use máquinas de teste, nunca a máquina de operação. Anexe ao relatório de release os prints e a saída de `lethe report` de cada máquina.

## Preparação (uma vez por máquina)

1. Instale o pacote da release (`.deb`/`.rpm`) ou copie `lethe` e `lethe-gui` para a mesma pasta, com dono root e permissão `0755`. Confira o hash com `lethe version` e as notas da release.
2. Tenha à mão:
   - uma VPN WireGuard de teste com DNS próprio;
   - o Tor (o daemon do sistema e o Tor Browser);
   - duas redes Wi-Fi: a "real" e outra para trocar.
3. Crie a baseline **sem** a VPN, na rede real, com `lethe baseline create` (ele consulta o IP público e recusa túnel ligado), e o perfil com `lethe profile init`; ou use `lethe setup`, que pergunta tudo à mão.
4. `sudo lethe run -p PERFIL --guard off`, `lethe selftest` e Ctrl-C. O selftest completo precisa passar antes de qualquer teste em estrito.

## 1. GUI — GNOME/Wayland, GNOME/X11, KDE/Wayland e KDE/X11

Para cada combinação (escolha a sessão na tela de login):

| # | Passo | Esperado | ok |
|---|---|---|---|
| 1.1 | `sudo lethe run -p PERFIL --guard off` com a VPN ligada | A GUI abre sozinha (unidade transitória `lethe-gui-*.service` em `systemctl --user list-units 'lethe-gui*'`), o ícone aparece na bandeja e o painel mostra ARMED e a impressão digital da sessão | ☐ |
| 1.2 | Clicar no ícone da bandeja | Menu com o estado e o número de alertas, Abrir painel, Pânico, Selftest e Desarmar | ☐ |
| 1.3 | Fechar o painel pelo X | O painel some e a bandeja continua; "Abrir painel" o traz de volta | ☐ |
| 1.4 | Desligar a VPN (`wg-quick down`) | Em ≤ 500 ms aparece o alerta vermelho em tela cheia do TUN-001/NET-004, com o som e uma notificação crítica do agente. O ícone fica vermelho e mostra o contador | ☐ |
| 1.5 | No alerta: Esc, Alt+F4 e o X | Nada fecha o alerta | ☐ |
| 1.6 | Reconhecer sem motivo, depois sem passphrase | Nada acontece | ☐ |
| 1.7 | Reconhecer com motivo e a passphrase errada | Mensagem de prova rejeitada; o alerta continua | ☐ |
| 1.8 | Reconhecer com a passphrase certa | O alerta sai e o painel mostra "Alerta reconhecido". `lethe report` tem `alert.ack` e um `response.executed` do `alert_fullscreen` com `reported_by: gui` | ☐ |
| 1.9 | Só no X11: abrir o diálogo de reconhecer | Aparece o aviso de que o teclado pode ser lido no X11 | ☐ |
| 1.10 | Botão Pânico → Sim (guarda `strict`, rode de novo com `--guard strict`) | A rede para; o painel mostra o bloqueio e o botão "Sair do pânico". Sair do pânico pede a passphrase e só libera com o túnel de pé | ☐ |
| 1.11 | Selftest → Rápido | Resultado no painel, em cerca de 1 minuto | ☐ |
| 1.12 | Desarmar (passphrase) | Sessão encerrada; o painel mostra READY; `nft list ruleset` sem tabelas `lethe*` | ☐ |
| 1.13 | `sudo lethe run -p PERFIL --no-gui` | Nenhuma GUI abre; os alertas chegam pelas notificações | ☐ |
| 1.14 | Matar a GUI (`systemctl --user stop 'lethe-gui-*'`) com a sessão armada | A sessão segue armada; os alertas continuam pelas notificações | ☐ |

Anote, para cada desktop, se a janela de alerta ficou **acima de tudo** e se ganhou o foco. No GNOME/Wayland é esperado que não fique (spec §16.4): por isso a notificação e o som sempre acompanham o alerta.

## 2. TUI

| # | Passo | Esperado | ok |
|---|---|---|---|
| 2.1 | `sudo lethe run -p PERFIL --tui`, desligar a VPN | Tela vermelha inteira e sino a cada `ui.sound_repeat` | ☐ |
| 2.2 | `q` e Esc durante o alerta | Nada acontece | ☐ |
| 2.3 | `a`, motivo, passphrase | O alerta sai e a tela principal volta | ☐ |
| 2.4 | `q` fora do alerta | A TUI fecha; a sessão segue armada ("Ctrl-C desarma") | ☐ |

## 3. Wi-Fi e NetworkManager

| # | Passo | Esperado | ok |
|---|---|---|---|
| 3.1 | Armado, trocar para a outra rede Wi-Fi | NET-007 | ☐ |
| 3.2 | Rede Wi-Fi da baseline com autoconnect | HOST-008 no preflight | ☐ |
| 3.3 | MAC de fábrica na interface Wi-Fi | NET-008 | ☐ |
| 3.4 | Checagem de conectividade do NM ligada | NET-013 | ☐ |
| 3.5 | DHCP mandando o hostname (`dhcp-send-hostname=true`) | NET-014 | ☐ |
| 3.6 | Plugar um cabo ou um celular em USB tethering | NET-006 e, se houver rota, NET-004 | ☐ |

## 4. Tor e Tor Browser

| # | Passo | Esperado | ok |
|---|---|---|---|
| 4.1 | Perfil `egress.type: tor`, Tor do sistema rodando | Preflight OK; `discover --json` mostra `tor.socks` | ☐ |
| 4.2 | `sudo lethe run` com checks ativos ligados | `status --json` traz `exit.path: tor` e o país da saída (base geo presente) | ☐ |
| 4.3 | Abrir o Tor Browser e navegar | Nenhum NET-001/DNS-001 | ☐ |
| 4.4 | Navegador comum com WebRTC ligado, numa página de chamada | NET-012 ou PER-002 | ☐ |
| 4.5 | Parar o Tor | TUN-003 | ☐ |

## Fechamento

- Rode `lethe report` e `lethe verify` da última sessão de cada máquina e anexe-os.
- Qualquer ☐ sem marcação bloqueia a release, ou exige uma exceção registrada nas notas da release com o motivo.
