# Modo serviço (`lethed@<usuário>.service` ou `lethed.service`)

Para máquinas dedicadas, em que o lethe fica sempre instalado. No modo portátil (`sudo lethe run`) nada disto é necessário.

## O que o pacote instala

| Arquivo | Para quê |
|---|---|
| `/usr/bin/lethe` | CLI e daemon |
| `/usr/bin/lethe-gui` | GUI (pacote `lethe-gui`, opcional) |
| `/usr/lib/systemd/system/lethed@.service` | daemon de um operador (a instância é o usuário): o mesmo que `lethed.service` com `LETHE_OPERATOR` e `~/lethe` já declarados |
| `/usr/lib/systemd/system/lethed.service` | daemon, como root com capabilities reduzidas (spec §19.3); operador num drop-in |
| `/usr/lib/systemd/user/lethe-agent.service` | agente de sessão, como o operador |

Nenhuma unidade é habilitada pelo pacote.

## Caminho curto: pela GUI

Com o perfil em `~/lethe` (o que o primeiro uso da GUI cria), não há nada para configurar. Com o serviço parado, o painel mostra o botão **Iniciar o lethe**. Ele pede ao systemd, pelo D-Bus, que suba `lethed@<seu usuário>.service`, e o polkit pede a senha de administrador. No terminal, o equivalente é:

```
sudo systemctl enable --now lethed@alice
```

As duas unidades usam o mesmo `/run/lethe`: `lethed@.service` declara `Conflicts=lethed.service`, então só uma roda por vez.

Para um `storage.dir` fora de `~/lethe`, ou uma home fora de `/home`, acrescente o caminho num drop-in (`sudo systemctl edit lethed@alice`, com `ReadWritePaths=<storage.dir>`).

## Configurar à mão (`lethed.service`)

1. Declare o operador e a pasta de armazenamento do perfil (`storage.dir`):

   ```
   sudo systemctl edit lethed
   ```

   ```ini
   [Service]
   Environment=LETHE_OPERATOR=alice
   ReadWritePaths=/media/alice/cofre/lethe
   ```

   - Sem `LETHE_OPERATOR`, o daemon não sobe e o `journalctl -u lethed` diz por quê. Ele recusa root e usuários inexistentes.
   - Sem `ReadWritePaths`, o `lethe arm` falha ao gravar a sessão: `ProtectSystem=strict` deixa o resto do disco só leitura.
   - Perfil e baseline podem ficar na home: `ProtectHome=read-only` deixa ler.

2. Suba o daemon:

   ```
   sudo systemctl enable --now lethed
   ```

3. Habilite o agente como o operador (não como root):

   ```
   systemctl --user enable --now lethe-agent
   ```

## Usar

- `lethe arm -p PERFIL`, `lethe status`, `lethe ack`, `lethe disarm`, como no modo portátil.
- O socket é `/run/lethe/lethe.sock`. Ele aceita só root e o operador; qualquer outro UID é recusado e registrado (`ipc.denied`).
- Cada processo do daemon atende uma sessão. Ao desarmar, ele termina e o systemd sobe outro para o próximo `arm`.

## Se algo der errado

- **O daemon morreu com a guarda estrita aplicada:** a rede fica fechada, de propósito. `sudo lethe status` mostra o bloqueio e como sair. `sudo lethe cleanup` remove as tabelas `lethe*`; reiniciar a máquina também resolve.
- **`systemctl status lethed` mostra `code=killed, signal=SYS`:** o seccomp matou o daemon por uma syscall fora da allowlist. Isso é um bug do lethe. Para coletar o que falta:
  1. `sudo systemctl edit lethed` e acrescente `Environment=LETHE_SECCOMP=log`;
  2. reproduza;
  3. `journalctl -k | grep type=1326` lista as syscalls;
  4. anexe a lista ao relatório do bug e **tire a linha**, porque nesse modo o filtro só registra e não mata.
- **O agente não conecta:** `journalctl --user -u lethe-agent`. Ele tenta de novo a cada 5 s. Confira se o operador do drop-in é o mesmo usuário da sessão gráfica.
