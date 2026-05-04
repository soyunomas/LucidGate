# QUICKSTART - lucidgate

Guia minima para compilar y probar el proxy MITM HTTPS en Go.

## 1. Compilar

```bash
cd ~/GIT/lucidgate
make build
```

Esto genera `./build/lucidgate`.

## 2. Crear la CA local

```bash
./build/lucidgate --cert-dir=./certs &
sleep 1
pkill -f "./build/lucidgate"
```

Se crean `certs/ca.crt` y `certs/ca.key`.

Importa `~/GIT/lucidgate/certs/ca.crt` en Firefox:

`Ajustes -> Privacidad y Seguridad -> Certificados -> Ver certificados -> Autoridades -> Importar`

Marca "Confiar para identificar sitios web".

No compartas `certs/ca.key`.

## 3. Arrancar el proxy

```bash
cd ~/GIT/lucidgate
mkdir -p dumps
./build/lucidgate \
  --listen=127.0.0.1:8080 \
  --cert-dir=./certs \
  --dump-dir=./dumps \
  --log-bodies=true \
  --max-capture-bytes=8388608
```

Equivalente con variables de entorno:

```bash
LUCIDGATE_DUMP_DIR=./dumps \
LUCIDGATE_MAX_CAPTURE_BYTES=8388608 \
./build/lucidgate
```

## 4. Configurar Firefox

`Ajustes -> General -> Configuracion de red -> Configuracion manual del proxy`:

- HTTP Proxy: `127.0.0.1`, puerto `8080`
- HTTPS Proxy: `127.0.0.1`, puerto `8080`
- Marca "Usar tambien este proxy para HTTPS"

## 5. Verificar

```bash
make verify
```

La verificacion compila `build/lucidgate` y ejecuta un smoke test end-to-end
con una CA temporal y un upstream HTTPS local.

## Limpieza

```bash
pkill -f lucidgate
shred -u ./dumps/dump_*.jsonl 2>/dev/null || true
```
