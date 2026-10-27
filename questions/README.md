# Kubectl Exorcise 2026

Tienes 60 minutos para resolver tres incidentes de Kubernetes. Lee `q01.md`, `q02.md` y `q03.md`; cada archivo describe un reto y su YAML inicial correspondiente.

Aplica un manifiesto por reto:

```sh
cd questions
kubectl apply -f q01.yml
```

Cada YAML crea su propio namespace. El clúster debe permitir crear namespaces y recursos namespaced. Limita las correcciones al namespace del reto y conserva el comportamiento indicado en el enunciado.

Cuando resuelvas un reto, encontrarás su flag en los logs del workload correspondiente:

```sh
kubectl -n haunted-loop logs deploy/backoff-watcher
kubectl -n cursed-endpoints logs deploy/endpoint-watcher
kubectl -n possessed-sa logs deploy/possession-observer
```

Envía las tres flags en el formulario del evento. Los retos se probaron en Kubernetes **v1.34, v1.35, v1.36 y v1.37**. El clúster debe poder descargar las imágenes de GHCR, `registry.k8s.io` y Docker Hub. Una vez descargadas, la resolución no necesita internet.
