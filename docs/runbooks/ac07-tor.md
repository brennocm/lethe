# AC-07 por roteiro manual: descoberta do Tor e TUN-003

Use este roteiro quando o `TestE2E_AC07_TorDiscoveryAndStop` der SKIP por falta do binário `tor`.
Rode numa VM descartável ou num namespace de rede, **nunca** com o guarda `strict` no
namespace do host.

## Preparação

1. Instale o tor do sistema (`apt install tor` ou `dnf install tor`).
2. Em `/etc/tor/torrc` (ou num `torrc` próprio), deixe:

   ```
   ControlPort 127.0.0.1:9051
   CookieAuthentication 1
   ```

3. Reinicie o tor e espere o bootstrap: `journalctl -u tor -f` até aparecer `Bootstrapped 100%`.

## Passos

1. Crie um perfil com `egress.type: tor` e `guard.mode: off` (`lethe profile init`, depois edite).
2. `sudo lethe discover -p perfil.yaml`. **Esperado:** uma linha `tor <versão>: bootstrap 100%,
   circuit true, guards <ip:porta>` e os guards em `endpoints`, como `/tcp`.
3. Com bridges (opcional): use `UseBridges 1` e uma linha `Bridge obfs4 <ip:porta> ...`.
   **Esperado:** `bridges 1 (transports obfs4)` e o endereço da bridge em `endpoints`.
4. `sudo lethe preflight -p perfil.yaml`. **Esperado:** TUN-003 PASS.
5. `sudo lethe run -p perfil.yaml --guard off` e, em outro terminal, `sudo systemctl stop tor`.
   **Esperado:** em até 5 s, alerta **TUN-003 CRITICAL** com `reason: control_unreachable`.
6. `sudo systemctl start tor`. **Esperado:** o alerta passa para `resolved` depois do bootstrap.
7. Com `Bridge snowflake ...` e `UseBridges 1`, ponha `guard.mode: strict` no perfil e rode
   `sudo lethe preflight -p perfil.yaml`. **Esperado:** TUN-008 FAIL. Em VM ou namespace
   descartável, `lethe run --guard strict` deve recusar o arm citando TUN-008.

Anote a versão do tor e o resultado de cada passo no registro do marco.
