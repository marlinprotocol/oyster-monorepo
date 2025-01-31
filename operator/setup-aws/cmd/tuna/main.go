package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"sync"
	"time"

	"OysterSetupAWS/connect"
	"OysterSetupAWS/instances"
	"OysterSetupAWS/keypairs"

	log "github.com/sirupsen/logrus"
)

func main() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: false,
	})
	// log.SetLevel(log.DebugLevel)

	date := os.Args[1]

	keyPairName, exist := os.LookupEnv("KEY")
	if !exist {
		log.Panic("Key not set")
	}

	currentUser, err := user.Current()
	if err != nil {
		log.Panic(err.Error())
	}

	keyStoreLocation := "/home/" + currentUser.Username + "/.ssh/"
	profile, exist := os.LookupEnv("PROFILE")
	if !exist {
		log.Panic("Profile not set")
	}

	region, exist := os.LookupEnv("REGION")
	if !exist {
		log.Panic("Region not set")
	}

	keypairs.SetupKeys(keyPairName, keyStoreLocation, profile, region)
	privateKeyLocation := keyStoreLocation + "/" + keyPairName + ".pem"

	exist_amd64 := instances.CheckAMIFromNameTag("marlin/oyster/worker-tuna-amd64-"+date, profile, region)
	exist_arm64 := instances.CheckAMIFromNameTag("marlin/oyster/worker-tuna-arm64-"+date, profile, region)

	if !exist_arm64 && !exist_amd64 {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			create_ami(keyPairName, privateKeyLocation, profile, region, "amd64", date)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			create_ami(keyPairName, privateKeyLocation, profile, region, "arm64", date)
		}()
		wg.Wait()
	} else if exist_arm64 && !exist_amd64 {
		log.Info("arm64 AMI already exists.")
		create_ami(keyPairName, privateKeyLocation, profile, region, "amd64", date)
	} else if exist_amd64 && !exist_arm64 {
		log.Info("amd64 AMI already exists.")
		create_ami(keyPairName, privateKeyLocation, profile, region, "arm64", date)
	} else {
		log.Info("AMIs already exist.")
		return
	}

}

func create_ami(keyPairName string, keyStoreLocation string, profile string, region string, arch string, date string) {
	log.Info("Creating AMI for " + arch)
	name := "oyster_tuna_" + arch
	newInstanceID := ""
	exist, instance := instances.GetInstanceFromNameTag(name, profile, region)
	if exist {
		log.Info("Found Existing instance for ", arch)
		newInstanceID = *instance.InstanceId
	} else {
		newInstanceID = *instances.LaunchInstance(name, keyPairName, profile, region, arch, date)
		time.Sleep(1 * time.Minute)
		instance = instances.GetInstanceDetails(newInstanceID, profile, region)
	}

	client := connect.NewSshClient(
		"ubuntu",
		*(instance.PublicIpAddress),
		22,
		keyStoreLocation,
	)
	SetupPreRequisites(client, *(instance.PublicIpAddress), newInstanceID, profile, region, arch)

	amiName := "marlin/oyster/worker-tuna-" + arch + "-" + date
	instances.CreateAMI(amiName, newInstanceID, profile, region, arch)
	time.Sleep(7 * time.Minute)
	TearDown(newInstanceID, profile, region)
}

func SetupPreRequisites(client *connect.SshClient, host string, instanceID string, profile string, region string, arch string) {
	RunCommand(client, "sudo apt-get -y update && sudo apt-get -y upgrade")
	RunCommand(client, "sudo apt-get -y install file build-essential")
	RunCommand(client, "grep /boot/config-$(uname -r) -e NITRO_ENCLAVES")
	RunCommand(client, "sudo apt-get -y install linux-modules-extra-aws")
	RunCommand(client, "sudo apt-get -y install docker.io")
	RunCommand(client, "sudo systemctl start docker")
	RunCommand(client, "sudo systemctl enable docker")
	RunCommand(client, "sudo usermod -aG docker ubuntu")
	RunCommand(client, "rm -rf aws-nitro-enclaves-cli && git clone https://github.com/aws/aws-nitro-enclaves-cli.git")
	RunCommand(client, "cd aws-nitro-enclaves-cli && THIS_USER=\"$(whoami)\"")
	RunCommand(client, "cd aws-nitro-enclaves-cli && export NITRO_CLI_INSTALL_DIR=/")
	RunCommand(client, "cd aws-nitro-enclaves-cli && (docker ps -a -q | xargs -r sudo docker stop) && (docker ps -a -q | xargs -r sudo docker rm) && sudo docker image prune --all -f  && make vsock-proxy")
	RunCommand(client, "cd aws-nitro-enclaves-cli && (docker ps -a -q | xargs -r sudo docker stop) && (docker ps -a -q | xargs -r sudo docker rm) && sudo docker image prune --all -f && make nitro-cli")
	RunCommand(client, `cd aws-nitro-enclaves-cli && (docker ps -a -q | xargs -r sudo docker stop) && (docker ps -a -q | xargs -r sudo docker rm) && sudo docker image prune --all -f  &&
						sudo make NITRO_CLI_INSTALL_DIR=/ install &&
						source /etc/profile.d/nitro-cli-env.sh &&
						echo source /etc/profile.d/nitro-cli-env.sh >> ~/.bashrc &&
						nitro-cli-config -i`)
	RunCommand(client, "sudo systemctl enable nitro-enclaves-allocator.service")
	RunCommand(client, "sudo apt -y install network-manager")

	// proxies
	RunCommand(client, "wget -O vsock-to-ip-raw-outgoing https://artifacts.marlin.org/oyster/binaries/vsock-to-ip-raw-outgoing_v1.0.0_linux_"+arch)
	RunCommand(client, "chmod +x vsock-to-ip-raw-outgoing")
	RunCommand(client, "wget -O ip-to-vsock-raw-incoming https://artifacts.marlin.org/oyster/binaries/ip-to-vsock-raw-incoming_v1.0.0_linux_"+arch)
	RunCommand(client, "chmod +x ip-to-vsock-raw-incoming")

	// init server
	RunCommand(client, "wget -O oyster-init-server https://artifacts.marlin.org/oyster/binaries/init-server_v1.0.0_linux_"+arch)
	RunCommand(client, "chmod +x oyster-init-server")

	// supervisord
	RunCommand(client, "sudo apt-get -y install supervisor")

	// proxies conf
	connect.TransferFile(client.Config, host, "./cmd/tuna/proxies.conf", "/home/ubuntu/proxies.conf")
	RunCommand(client, "sudo mv /home/ubuntu/proxies.conf /etc/supervisor/conf.d/proxies.conf")

	// init server conf
	connect.TransferFile(client.Config, host, "./cmd/tuna/oyster-init-server.conf", "/home/ubuntu/oyster-init-server.conf")
	RunCommand(client, "sudo mv /home/ubuntu/oyster-init-server.conf /etc/supervisor/conf.d/oyster-init-server.conf")

	RunCommand(client, "sudo supervisorctl reload")

	RunCommand(client, "sudo rm -r /home/ubuntu/aws-nitro-enclaves-cli")
	RunCommand(client, "sudo rm /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys")
}

func RunCommand(client *connect.SshClient, cmd string) string {
	fmt.Println("============================================================================================")
	log.Info(cmd)
	fmt.Println("")

	output, err := client.RunCommand(cmd)

	if err != nil {
		log.Warn("SSH run command error", err)

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Retry? ")
		line, _ := reader.ReadString('\n')

		if line == "Y\n" || line == "yes\n" {
			return RunCommand(client, cmd)
		} else if line != "continue\n" {
			os.Exit(1)
		}
	}
	return output
}

func TearDown(instanceID string, profile string, region string) {
	instances.TerminateInstance(instanceID, profile, region)
}
