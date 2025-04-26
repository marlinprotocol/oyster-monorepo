using Workerd = import "/workerd/workerd.capnp";

const oysterConfig :Workerd.Config = (
  services = [ (name = "main", worker = .oysterWorker) ],
  sockets = [ ( name = "http", address = "*:8080", http = (), service = "main" ) ]
);

const oysterWorker :Workerd.Worker = (
  modules = [
    (name = "main", esModule = embed "worker.js")
  ],
  compatibilityDate = "2023-03-07",
);
