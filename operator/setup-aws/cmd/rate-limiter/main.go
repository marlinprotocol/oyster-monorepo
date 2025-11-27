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
	log.SetFormatter(
		&log.TextFormatter{
			FullTimestamp: false,
		},
	)
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

	exist_amd64 := instances.CheckAMIFromNameTag("marlin/oyster/worker-rate-limiter-amd64-"+date, profile, region)
	exist_arm64 := instances.CheckAMIFromNameTag("marlin/oyster/worker-rate-limiter-arm64-"+date, profile, region)

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
	name := "oyster_rate_limiter_" + arch
	newInstanceID := ""
	exist, instance := instances.GetInstanceFromNameTag(name, profile, region)

	if exist {
		log.Info("Found Existing instance for ", arch)
		newInstanceID = *instance.InstanceId
	} else {
		newInstanceID = *instances.LaunchInstance(name, keyPairName, profile, region, arch, date) // TODO: launch instance with minimal image
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

	amiName := "marlin/oyster/worker-rate-limiter-" + arch + "-" + date
	instances.CreateAMI(amiName, newInstanceID, profile, region, arch)
	time.Sleep(7 * time.Minute)
	TearDown(newInstanceID, profile, region)
}

func SetupPreRequisites(client *connect.SshClient, publicIP string, instanceID string, profile string, region string, arch string) {
	RunCommand(client, "sudo apt-get -y update && sudo apt-get -y upgrade")

	// copy scripts
	connect.TransferFile(client.Config, publicIP, "./cmd/rate-limiter/add_rl.sh", "/home/ubuntu/add_rl.sh")
	connect.TransferFile(client.Config, publicIP, "./cmd/rate-limiter/common_rl.sh", "/home/ubuntu/common_rl.sh")
	connect.TransferFile(client.Config, publicIP, "./cmd/rate-limiter/remove_rl.sh", "/home/ubuntu/remove_rl.sh")

	// Setup nftables for nat
	RunCommand(client, "sudo apt install -y nftables")
	RunCommand(client, `cat <<EOF | sudo tee /etc/nftables.conf > /dev/null
#!/usr/sbin/nft -f

flush ruleset

table ip raw {
    chain prerouting {
        type filter hook prerouting priority raw; policy accept;
    }
	chain postrouting {
        type filter hook postrouting priority raw; policy accept;
    }
}
EOF`)
	RunCommand(client, "sudo systemctl enable nftables")
	// RunCommand(client, "sudo systemctl start nftables") // TODO check if its needed, mostly no, after restart it will be started automatically

	// Setup traffic control
	RunCommand(client, "sudo apt-get -y install iproute2")

	// Enable IP forwarding
	RunCommand(client, "echo \"net.ipv4.ip_forward = 1\" | sudo tee /etc/sysctl.d/99-ip-forward.conf")

	// Remove ssh authorized keys
	RunCommand(client, "sudo rm /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys")

}

// TODO: put it in lib
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
