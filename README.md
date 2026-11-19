<p align="center">
  <img src="docs/assets/lethe-logo.webp" alt="lethe" width="520">
</p>

# lethe

Monitor local de OpSec para Linux. Enquanto você trabalha atrás de uma VPN e/ou do Tor, o lethe
descobre o túnel, confere a configuração antes de começar, vigia cada interface de saída por
tráfego que fuja do túnel (IP, DNS, IPv6, WebRTC/STUN, broadcasts na LAN), pode bloqueá-lo com
nftables (falha fechada) e grava um log da sessão cifrado, encadeado por hash e assinado.

Tudo se faz pelo painel (`lethe-gui`). O terminal só é preciso para instalar.

## Instalar

Do repositório interno da instituição (ou dos arquivos da release):

```sh
sudo apt install ./lethe_*.deb ./lethe-gui_*.deb     # Debian, Ubuntu
sudo dnf install ./lethe-*.rpm ./lethe-gui-*.rpm     # Fedora
```

O pacote `lethe-gui` puxa sozinho as bibliotecas gráficas de que precisa. Confira o binário com
`lethe version` contra as notas da release.

## Usar

1. **Abra o lethe** pelo menu de aplicativos, ou com `lethe-gui`.
2. **Primeiro uso** (uma vez): com a VPN **desligada**, na sua rede real, o painel pede a
   identidade da operação, descobre o IP público e os DNS da rede quando você pede, e uma
   passphrase digitada duas vezes. Ele cria `~/lethe/profile.yaml` e `~/lethe/baseline.age`.
   Não há chave para gerenciar: o único segredo é a passphrase. Guarde-a **fora** da máquina.
3. **Iniciar o lethe**: o painel sobe o serviço e o sistema pede a senha de administrador.
4. **Ligue a VPN** (ou o Tor) e clique em **Iniciar sessão**. Comece em *Só observar*; a proteção
   *Estrita* aparece depois de um **Selftest** aprovado nesta máquina.
5. Durante a sessão, a **Visão geral** responde "estou coberto?" e a rota mostra por onde a web
   vê você. As outras páginas detalham o IP e o DNS, os eventos, o guarda e os checks. Um vazamento crítico abre um alerta vermelho em tela cheia que só fecha com motivo e
   passphrase. **Pânico** bloqueia a rede na hora.
6. **Encerrar sessão** pede a passphrase, tira as regras e fecha o log. O relatório da sessão
   fica em **Relatórios**, na página **Sessão**.

Outras redes reais (casa, escritório, café): **Registrar a rede atual**, sem a VPN, para que o IP
e os DNS delas também contem como vazamento.

## Se a rede ficar bloqueada

O bloqueio é sempre de propósito e sempre tem saída. O painel diz o que está bloqueado, por quê
e como sair: **Sair do pânico**, **Encerrar sessão** ou, depois de uma queda, **Liberar a rede**
(pede a senha de administrador). Sem painel: `sudo lethe cleanup`. Reiniciar a máquina também
libera. Detalhes em [`docs/runbooks/crash-recovery.md`](docs/runbooks/crash-recovery.md).

## Documentação

| Para quem | Onde |
|---|---|
| Operador | [`operation.md`](docs/runbooks/operation.md) (roteiro de uma operação), [`crash-recovery.md`](docs/runbooks/crash-recovery.md), [`session-verification.md`](docs/runbooks/session-verification.md) |
| Quem instala em máquinas dedicadas | [`service-mode.md`](docs/runbooks/service-mode.md) |
| Dono do projeto (release) | [`release.md`](docs/runbooks/release.md), [`manual-acceptance.md`](docs/runbooks/manual-acceptance.md), [`ac07-tor.md`](docs/runbooks/ac07-tor.md) |
| Quem desenvolve | [`spec.md`](spec.md) (escopo), [`AGENTS.md`](AGENTS.md) (estado e regras), [`docs/adr`](docs/adr) (decisões) |

## Desenvolver

```sh
mise install          # toolchain fixada (Go, linters, nfpm)
mise run gui          # compila a GUI e abre (instala os headers de OpenGL/X11/Wayland se faltarem)
mise run check        # definição de pronto: format, lint, fronteiras, vet, testes
mise run e2e          # testes em network namespaces (user namespaces ou sudo -E)
mise run build        # binário estático em bin/lethe
mise run release -- VERSÃO --gui   # pacotes deb/rpm, SBOM e SHA256SUMS (sem assinar)
```

Nunca arme a proteção estrita, nem acione o pânico, numa máquina cuja rede você precisa, a não
ser que seja essa a intenção: é exatamente para isso que eles servem. Os testes que aplicam
nftables rodam só nos namespaces do `test/netlab`.

## Licença

A definir pelo dono antes da primeira release. As licenças das dependências e dos dados
embutidos estão em [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md).
