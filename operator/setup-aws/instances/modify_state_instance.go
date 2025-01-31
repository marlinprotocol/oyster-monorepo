package instances

import (

	// "encoding/json"
	// "io/ioutil"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	log "github.com/sirupsen/logrus"
)

func CreateInstance(name string, client *ec2.EC2, imageId string, minCount int, maxCount int, instanceType string, keyName string, arch string, subnetId string, secGroupID string) (*ec2.Reservation, error) {
	res, err := client.RunInstances(&ec2.RunInstancesInput{
		ImageId:        aws.String(imageId),
		MinCount:       aws.Int64(int64(minCount)),
		MaxCount:       aws.Int64(int64(maxCount)),
		InstanceType:   aws.String(instanceType),
		KeyName:        aws.String(keyName),
		EnclaveOptions: &ec2.EnclaveOptionsRequest{Enabled: &[]bool{true}[0]},
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{{
			Ebs: &[]ec2.EbsBlockDevice{{
				VolumeSize: &[]int64{12}[0],
				VolumeType: &[]string{ec2.VolumeTypeGp3}[0],
			}}[0],
			DeviceName: &[]string{"/dev/sda1"}[0],
		}},
		SecurityGroupIds: []*string{
			aws.String(secGroupID),
		},
		SubnetId: &subnetId,
	})

	if err != nil {
		return nil, err
	}

	_, errtag := client.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{res.Instances[0].InstanceId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(name),
			},
			{
				Key:   aws.String("manager"),
				Value: aws.String("marlin"),
			},
			{
				Key:   aws.String("project"),
				Value: aws.String("oyster"),
			},
		},
	})
	if errtag != nil {
		log.Warn("Could not create tags for instance", res.Instances[0].InstanceId, errtag)
	}
	return res, nil
}

func LaunchInstance(name string, keyPairName string, profile string, region string, arch string, date string) *string {
	log.Info("Launching Instance.")

	ec2Client := GetClient(profile, region)

	keyName := keyPairName
	owner := "099720109477" // Canonical/Ubuntu
	fname := "name"
	fvalues := "ubuntu-minimal/images/hvm-ssd-gp3/ubuntu-noble-24.04-" + arch + "-minimal-" + date
	imageRes, err := ec2Client.DescribeImages(&ec2.DescribeImagesInput{
		Owners: []*string{&owner},
		Filters: []*ec2.Filter{{
			Name:   &fname,
			Values: []*string{&fvalues},
		}},
	})
	if err != nil {
		log.Error("Could not find image", err)
		return nil
	}

	imageId := *imageRes.Images[0].ImageId

	instanceType := "c6a.xlarge"
	if arch == "arm64" {
		instanceType = "c6g.xlarge"
	}
	// instanceType := "c6a.xlarge"
	// instanceType := "c6g.xlarge"
	minCount := 1
	maxCount := 1
	// imageId := "ami-05ba3a39a75be1ec4" //x86
	// imageId := "ami-0296ecdacc0d49d5a" //arm
	subnet := GetSubnet(ec2Client)
	if subnet == nil {
		log.Error("Could not find subnet")
		return nil
	}

	securityGroup := GetSecurityGroup(ec2Client)
	if securityGroup == nil {
		log.Error("Could not find security group")
		return nil
	}

	subnetId := *subnet.SubnetId
	securityGroupID := *securityGroup.GroupId
	newInstance, err := CreateInstance(name, ec2Client, imageId, minCount, maxCount, instanceType, keyName, arch, subnetId, securityGroupID)
	if err != nil {
		log.Error("Couldn't create new instance", err)
		return nil
	}
	instanceID := newInstance.Instances[0].InstanceId

	log.Info("Instance Created!")

	return instanceID
}

func RebootInstance(instanceID string, profile string, region string) {
	// Create new EC2 client
	svc := GetClient(profile, region)

	// We set DryRun to true to check to see if the instance exists and we have the
	// necessary permissions to monitor the instance.
	input := &ec2.RebootInstancesInput{
		InstanceIds: []*string{
			&instanceID,
		},
		DryRun: aws.Bool(true),
	}
	result, err := svc.RebootInstances(input)
	awsErr, ok := err.(awserr.Error)

	// If the error code is `DryRunOperation` it means we have the necessary
	// permissions to Start this instance
	if ok && awsErr.Code() == "DryRunOperation" {
		// Let's now set dry run to be false. This will allow us to reboot the instances
		input.DryRun = aws.Bool(false)
		result, err = svc.RebootInstances(input)
		if err != nil {
			log.Error("Error rebooting instance: ", err)
		} else {
			log.Info("Reboot Success!", result)
		}
	} else { // This could be due to a lack of permissions
		log.Warn("Error in reboot dry run: ", err)
	}
	log.Info("Reboot Successful!")
}

func TerminateInstance(instanceID string, profile string, region string) {
	// Create new EC2 client
	svc := GetClient(profile, region)

	_, err := svc.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{&instanceID},
	})
	if err != nil {
		log.Warn("Couldn't terimate instance: ", err)
	}

	log.Info("Termination Successful!")
}

func CreateAMI(amiName string, instanceID string, profile string, region string, arch string) {
	client := GetClient(profile, region)
	resource := ec2.ResourceTypeImage
	res, err := client.CreateImage(&ec2.CreateImageInput{
		InstanceId: aws.String(instanceID),
		Name:       aws.String(amiName),
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{{
			Ebs: &[]ec2.EbsBlockDevice{{
				VolumeSize: &[]int64{8}[0],
				VolumeType: &[]string{ec2.VolumeTypeGp3}[0],
			}}[0],
			DeviceName: &[]string{"/dev/sda1"}[0],
		}},
		TagSpecifications: []*ec2.TagSpecification{{
			ResourceType: &resource,
			Tags: []*ec2.Tag{
				{
					Key:   aws.String("manager"),
					Value: aws.String("marlin"),
				},
				{
					Key:   aws.String("project"),
					Value: aws.String("oyster"),
				},
			},
		}},
	})
	if err != nil {
		log.Panic("Error creating image", err)
	}

	log.Info("Image created: ", res.ImageId)
}

func GetClient(profile string, region string) *ec2.EC2 {

	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: profile,
		Config: aws.Config{
			Region: aws.String(region),
		},
	})

	if err != nil {
		log.Error("Failed to initialize new session", err)
		return nil
	}

	ec2Client := ec2.New(sess)

	return ec2Client
}
