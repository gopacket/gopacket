package main

import (
	"fmt"
	"log"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func main() {
	// Example: Using ENIP constants
	exampleENIPConstants()

	// Example: Using CIP constants
	exampleCIPConstants()

	// Example: Using Modbus constants
	exampleModbusConstants()

	fmt.Println("\nFor live packet capture, see the usage example functions.")
}

func exampleENIPConstants() {
	fmt.Println("═══════════════════════════════════════")
	fmt.Println("ENIP Constants Usage Examples")
	fmt.Println("═══════════════════════════════════════\n")

	// Example ENIP commands
	commands := []layers.ENIPCommand{
		layers.ENIPCommandRegisterSession,
		layers.ENIPCommandSendRRData,
		layers.ENIPCommandSendUnitData,
		layers.ENIPCommandUnregisterSession,
	}

	for _, cmd := range commands {
		fmt.Printf("Command: 0x%04X = %s\n", uint16(cmd), cmd.String())
	}

	// Example ENIP status codes
	fmt.Println("\nStatus Codes:")
	statuses := []layers.ENIPStatus{
		layers.ENIPStatusSuccess,
		layers.ENIPStatusInvalidCommand,
		layers.ENIPStatusInvalidSessionHandle,
	}

	for _, status := range statuses {
		fmt.Printf("Status: 0x%04X = %s\n", uint32(status), status.String())
	}
}

func exampleCIPConstants() {
	fmt.Println("\n═══════════════════════════════════════")
	fmt.Println("CIP Constants Usage Examples")
	fmt.Println("═══════════════════════════════════════\n")

	// Example CIP services
	services := []layers.CIPService{
		layers.CIPServiceGetAttributeSingle,
		layers.CIPServiceSetAttributeSingle,
		layers.CIPServiceMultipleServicePacket,
		layers.CIPServiceForwardOpen,
		layers.CIPServiceForwardClose,
	}

	for _, svc := range services {
		fmt.Printf("Service: 0x%02X = %s\n", byte(svc), svc.String())
		// Show how response looks
		response := svc | layers.CIPServiceResponseMask
		fmt.Printf("  Response: 0x%02X = %s\n", byte(response), response.String())
	}

	// Example CIP status codes
	fmt.Println("\nStatus Codes:")
	statuses := []layers.CIPStatus{
		layers.CIPStatusSuccess,
		layers.CIPStatusServiceNotSupported,
		layers.CIPStatusInvalidAttributeValue,
		layers.CIPStatusObjectDoesNotExist,
	}

	for _, status := range statuses {
		fmt.Printf("Status: 0x%02X = %s\n", byte(status), status.String())
	}
}

// ExampleLiveCapture shows how to use these constants in real packet processing
func ExampleLiveCapture() {
	// Open a PCAP file or live interface
	handle, err := pcap.OpenOffline("industrial_traffic.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Process ENIP packets
		if enipLayer := packet.Layer(layers.LayerTypeENIP); enipLayer != nil {
			enip := enipLayer.(*layers.ENIP)

			// Use exported constants for comparison
			switch enip.Command {
			case layers.ENIPCommandRegisterSession:
				fmt.Printf("Register Session - Handle: 0x%08X\n", enip.SessionHandle)

			case layers.ENIPCommandSendRRData:
				fmt.Printf("SendRRData - Session: 0x%08X\n", enip.SessionHandle)

			case layers.ENIPCommandSendUnitData:
				fmt.Printf("SendUnitData - Session: 0x%08X\n", enip.SessionHandle)
			}

			// Check status using constants
			if enip.Status != uint32(layers.ENIPStatusSuccess) {
				fmt.Printf("⚠️  Error: %s\n", layers.ENIPStatus(enip.Status).String())
			}
		}

		// Process CIP packets
		if cipLayer := packet.Layer(layers.LayerTypeCIP); cipLayer != nil {
			cip := cipLayer.(*layers.CIP)

			service := layers.CIPService(cip.ServiceID)

			if cip.Response {
				fmt.Printf("CIP Response: %s\n", service.String())

				status := layers.CIPStatus(cip.Status)
				if status != layers.CIPStatusSuccess {
					fmt.Printf("⚠️  Error: %s\n", status.String())
				}
			} else {
				fmt.Printf("CIP Request: %s\n", service.String())
				fmt.Printf("  Class: 0x%04X, Instance: 0x%04X\n",
					cip.ClassID, cip.InstanceID)
			}
		}
	}
}

