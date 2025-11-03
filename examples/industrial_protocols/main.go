package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

var (
	iface         = flag.String("i", "", "Network interface to capture from (required)")
	showConstants = flag.Bool("show-constants", false, "Display protocol constants and exit")
	snaplen       = flag.Int("snaplen", 65536, "Snapshot length for packet capture")
	promisc       = flag.Bool("promisc", true, "Enable promiscuous mode")
	timeout       = flag.Duration("timeout", 30*time.Second, "Read timeout")
	filter        = flag.String("filter", "tcp port 502 or tcp port 44818 or tcp port 2222", "BPF filter (default: Modbus, ENIP, CIP ports)")
)

// run tests for industrial protocols: go test -v -run "TestModbus|TestENIP|TestCIP" ./layers
func main() {
	flag.Parse()

	// If user wants to see constants, show them and exit
	if *showConstants {
		printAllConstants()
		return
	}

	// Validate interface is provided
	if *iface == "" {
		fmt.Println("Available network interfaces:")
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		for _, device := range devices {
			fmt.Printf("  %s", device.Name)
			if device.Description != "" {
				fmt.Printf(" (%s)", device.Description)
			}
			fmt.Println()
			for _, address := range device.Addresses {
				fmt.Printf("    IP: %s\n", address.IP)
			}
		}
		fmt.Println("\nUsage: Use -i <interface> to specify interface")
		fmt.Println("       Use -show-constants to display protocol constants")
		os.Exit(1)
	}

	// Open the network interface for live capture
	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, *timeout)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", *iface, err)
	}
	defer handle.Close()

	// Set BPF filter
	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	fmt.Printf("╔════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  Industrial Protocol Monitor - Live Capture Mode          ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════════╝\n")
	fmt.Printf("Interface: %s\n", *iface)
	fmt.Printf("Filter:    %s\n", *filter)
	fmt.Printf("Listening for ENIP, CIP, and Modbus TCP packets...\n")
	fmt.Printf("Press Ctrl+C to stop\n\n")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0

	for packet := range packetSource.Packets() {
		packetCount++
		processPacket(packet, packetCount)
	}
}

func processPacket(packet gopacket.Packet, count int) {
	timestamp := packet.Metadata().Timestamp

	// Check for ENIP packets
	if enipLayer := packet.Layer(layers.LayerTypeENIP); enipLayer != nil {
		processENIP(enipLayer.(*layers.ENIP), packet, count, timestamp)
		return
	}

	// Check for CIP packets
	if cipLayer := packet.Layer(layers.LayerTypeCIP); cipLayer != nil {
		processCIP(cipLayer.(*layers.CIP), packet, count, timestamp)
		return
	}

	// Check for Modbus TCP packets
	if modbusLayer := packet.Layer(layers.LayerTypeModbus); modbusLayer != nil {
		processModbus(modbusLayer.(*layers.Modbus), packet, count, timestamp)
		return
	}
}

func processENIP(enip *layers.ENIP, packet gopacket.Packet, count int, timestamp time.Time) {
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Packet #%d [%s] - ENIP/CIP\n", count, timestamp.Format("15:04:05.000000"))

	// Get network info
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		fmt.Printf("Source: %s → Destination: %s\n", src, dst)
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		fmt.Printf("TCP: %d → %d\n", tcp.SrcPort, tcp.DstPort)
	}

	fmt.Printf("\nENIP Header:\n")
	fmt.Printf("  Command:        0x%04X (%s)\n", enip.Command, layers.ENIPCommand(enip.Command).String())
	fmt.Printf("  Session Handle: 0x%08X\n", enip.SessionHandle)
	fmt.Printf("  Status:         0x%08X", enip.Status)

	status := layers.ENIPStatus(enip.Status)
	if status != layers.ENIPStatusSuccess {
		fmt.Printf(" ⚠️  %s", status.String())
	} else {
		fmt.Printf(" ✓ %s", status.String())
	}
	fmt.Println()
	fmt.Printf("  Length:         %d bytes\n", enip.Length)

	// Check for embedded CIP
	if cipLayer := packet.Layer(layers.LayerTypeCIP); cipLayer != nil {
		cip := cipLayer.(*layers.CIP)
		fmt.Printf("\nEmbedded CIP:\n")
		printCIPDetails(cip)
	}

	fmt.Println()
}

func processCIP(cip *layers.CIP, packet gopacket.Packet, count int, timestamp time.Time) {
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Packet #%d [%s] - CIP\n", count, timestamp.Format("15:04:05.000000"))

	// Get network info
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		fmt.Printf("Source: %s → Destination: %s\n", src, dst)
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		fmt.Printf("TCP: %d → %d\n", tcp.SrcPort, tcp.DstPort)
	}

	fmt.Printf("\nCIP Message:\n")
	printCIPDetails(cip)
	fmt.Println()
}

func printCIPDetails(cip *layers.CIP) {
	service := layers.CIPService(cip.ServiceID)

	if cip.Response {
		fmt.Printf("  Type:     Response\n")
		fmt.Printf("  Service:  0x%02X (%s)\n", byte(service), service.String())
		fmt.Printf("  Status:   0x%02X", cip.Status)

		status := layers.CIPStatus(cip.Status)
		if status != layers.CIPStatusSuccess {
			fmt.Printf(" ⚠️  %s", status.String())
		} else {
			fmt.Printf(" ✓ %s", status.String())
		}
		fmt.Println()

		if len(cip.Data) > 0 {
			fmt.Printf("  Data:     %d bytes\n", len(cip.Data))
		}
	} else {
		fmt.Printf("  Type:     Request\n")
		fmt.Printf("  Service:  0x%02X (%s)\n", byte(service), service.String())
		fmt.Printf("  Class:    0x%04X\n", cip.ClassID)
		fmt.Printf("  Instance: 0x%04X\n", cip.InstanceID)

		if len(cip.Data) > 0 {
			fmt.Printf("  Data:     %d bytes\n", len(cip.Data))
		}
	}
}

func processModbus(modbus *layers.Modbus, packet gopacket.Packet, count int, timestamp time.Time) {
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Packet #%d [%s] - Modbus TCP\n", count, timestamp.Format("15:04:05.000000"))

	// Get network info
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		src, dst := netLayer.NetworkFlow().Endpoints()
		fmt.Printf("Source: %s → Destination: %s\n", src, dst)
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		fmt.Printf("TCP: %d → %d\n", tcp.SrcPort, tcp.DstPort)
	}

	fmt.Printf("\nMBAP Header:\n")
	fmt.Printf("  Transaction ID: 0x%04X\n", modbus.TransactionID)
	fmt.Printf("  Protocol ID:    0x%04X", modbus.ProtocolID)
	if modbus.ProtocolID != 0 {
		fmt.Printf(" ⚠️  (Expected 0 for Modbus)")
	}
	fmt.Println()
	fmt.Printf("  Length:         %d bytes\n", modbus.Length)
	fmt.Printf("  Unit ID:        %d\n", modbus.UnitID)

	fmt.Printf("\nModbus PDU:\n")
	functionCode := modbus.GetFunction()

	if modbus.IsException() {
		fmt.Printf("  Type:          Exception Response ⚠️\n")
		fmt.Printf("  Function Code: 0x%02X (%s)\n", byte(functionCode&^layers.ModbusFuncCodeExceptionMask), functionCode.String())

		excCode := modbus.GetExceptionCode()
		if excCode != 0 {
			fmt.Printf("  Exception:     0x%02X (%s)\n", byte(excCode), excCode.String())
		}
	} else {
		fmt.Printf("  Function Code: 0x%02X (%s)\n", byte(functionCode), functionCode.String())

		if len(modbus.ReqResp) > 0 {
			fmt.Printf("  Data:          %d bytes\n", len(modbus.ReqResp))

			// Show first few bytes of data for common functions
			switch functionCode {
			case layers.ModbusFuncCodeReadCoils,
				layers.ModbusFuncCodeReadDiscreteInputs,
				layers.ModbusFuncCodeReadHoldingRegisters,
				layers.ModbusFuncCodeReadInputRegisters:
				if len(modbus.ReqResp) >= 4 {
					addr := uint16(modbus.ReqResp[0])<<8 | uint16(modbus.ReqResp[1])
					quantity := uint16(modbus.ReqResp[2])<<8 | uint16(modbus.ReqResp[3])
					fmt.Printf("    Address:  0x%04X (%d)\n", addr, addr)
					fmt.Printf("    Quantity: %d\n", quantity)
				}
			}
		}
	}

	fmt.Println()
}

func printAllConstants() {
	fmt.Printf("╔════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║     Industrial Protocol Constants Reference               ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════════╝\n\n")

	printENIPConstants()
	printCIPConstants()
	printModbusConstants()
}

func printENIPConstants() {
	fmt.Println("═══════════════════════════════════════")
	fmt.Println("ENIP Constants")
	fmt.Println("═══════════════════════════════════════")

	fmt.Println("\nCommands:")
	commands := []layers.ENIPCommand{
		layers.ENIPCommandNOP,
		layers.ENIPCommandListServices,
		layers.ENIPCommandListIdentity,
		layers.ENIPCommandListInterfaces,
		layers.ENIPCommandRegisterSession,
		layers.ENIPCommandUnregisterSession,
		layers.ENIPCommandSendRRData,
		layers.ENIPCommandSendUnitData,
	}

	for _, cmd := range commands {
		fmt.Printf("  0x%04X  %s\n", uint16(cmd), cmd.String())
	}

	fmt.Println("\nStatus Codes:")
	statuses := []layers.ENIPStatus{
		layers.ENIPStatusSuccess,
		layers.ENIPStatusInvalidCommand,
		layers.ENIPStatusInsufficientMemory,
		layers.ENIPStatusIncorrectData,
		layers.ENIPStatusInvalidSessionHandle,
		layers.ENIPStatusInvalidLength,
		layers.ENIPStatusUnsupportedProtocol,
	}

	for _, status := range statuses {
		fmt.Printf("  0x%08X  %s\n", uint32(status), status.String())
	}
	fmt.Println()
}

func printCIPConstants() {
	fmt.Println("═══════════════════════════════════════")
	fmt.Println("CIP Constants")
	fmt.Println("═══════════════════════════════════════")

	fmt.Println("\nServices:")
	services := []layers.CIPService{
		layers.CIPServiceGetAttributesAll,
		layers.CIPServiceSetAttributesAll,
		layers.CIPServiceGetAttributeList,
		layers.CIPServiceSetAttributeList,
		layers.CIPServiceReset,
		layers.CIPServiceStart,
		layers.CIPServiceStop,
		layers.CIPServiceCreate,
		layers.CIPServiceDelete,
		layers.CIPServiceMultipleServicePacket,
		layers.CIPServiceApplyAttributes,
		layers.CIPServiceGetAttributeSingle,
		layers.CIPServiceSetAttributeSingle,
		layers.CIPServiceFindNextObjectInstance,
		layers.CIPServiceRestore,
		layers.CIPServiceSave,
		layers.CIPServiceGetMember,
		layers.CIPServiceSetMember,
		layers.CIPServiceInsertMember,
		layers.CIPServiceRemoveMember,
		layers.CIPServiceGroupSync,
		layers.CIPServiceForwardClose,
		layers.CIPServiceUnconnectedSend,
		layers.CIPServiceForwardOpen,
		layers.CIPServiceGetConnectionData,
		layers.CIPServiceSearchConnectionData,
		layers.CIPServiceGetConnectionOwner,
	}

	for _, svc := range services {
		fmt.Printf("  0x%02X  %s\n", byte(svc), svc.String())
	}

	fmt.Println("\nStatus Codes:")
	statuses := []layers.CIPStatus{
		layers.CIPStatusSuccess,
		layers.CIPStatusConnectionFailure,
		layers.CIPStatusResourceUnavailable,
		layers.CIPStatusInvalidParameterValue,
		layers.CIPStatusPathSegmentError,
		layers.CIPStatusPathDestinationUnknown,
		layers.CIPStatusPartialTransfer,
		layers.CIPStatusConnectionLost,
		layers.CIPStatusServiceNotSupported,
		layers.CIPStatusInvalidAttributeValue,
		layers.CIPStatusAttributeListError,
		layers.CIPStatusAlreadyInRequestedMode,
		layers.CIPStatusObjectStateConflict,
		layers.CIPStatusObjectAlreadyExists,
		layers.CIPStatusAttributeNotSettable,
		layers.CIPStatusPrivilegeViolation,
		layers.CIPStatusDeviceStateConflict,
		layers.CIPStatusReplyDataTooLarge,
		layers.CIPStatusFragmentationOfPrimitiveValue,
		layers.CIPStatusNotEnoughData,
		layers.CIPStatusAttributeNotSupported,
		layers.CIPStatusTooMuchData,
		layers.CIPStatusObjectDoesNotExist,
		layers.CIPStatusServiceFragmentationSequence,
		layers.CIPStatusNoStoredAttributeData,
		layers.CIPStatusStoreOperationFailure,
		layers.CIPStatusRoutingFailure,
		layers.CIPStatusRoutingFailureBadSize,
		layers.CIPStatusRoutingFailureBadService,
		layers.CIPStatusInvalidParameter,
	}

	for _, status := range statuses {
		fmt.Printf("  0x%02X  %s\n", byte(status), status.String())
	}
	fmt.Println()
}

func printModbusConstants() {
	fmt.Println("═══════════════════════════════════════")
	fmt.Println("Modbus TCP Constants")
	fmt.Println("═══════════════════════════════════════")

	fmt.Println("\nFunction Codes:")
	functions := []layers.ModbusFunctionCode{
		layers.ModbusFuncCodeReadCoils,
		layers.ModbusFuncCodeReadDiscreteInputs,
		layers.ModbusFuncCodeReadHoldingRegisters,
		layers.ModbusFuncCodeReadInputRegisters,
		layers.ModbusFuncCodeWriteSingleCoil,
		layers.ModbusFuncCodeWriteSingleRegister,
		layers.ModbusFuncCodeReadExceptionStatus,
		layers.ModbusFuncCodeDiagnostics,
		layers.ModbusFuncCodeGetCommEventCounter,
		layers.ModbusFuncCodeGetCommEventLog,
		layers.ModbusFuncCodeWriteMultipleCoils,
		layers.ModbusFuncCodeWriteMultipleRegisters,
		layers.ModbusFuncCodeReportSlaveID,
		layers.ModbusFuncCodeReadFileRecord,
		layers.ModbusFuncCodeWriteFileRecord,
		layers.ModbusFuncCodeMaskWriteRegister,
		layers.ModbusFuncCodeReadWriteMultipleRegs,
		layers.ModbusFuncCodeReadFIFOQueue,
		layers.ModbusFuncCodeEncapsulatedInterface,
	}

	for _, fc := range functions {
		fmt.Printf("  0x%02X  %s\n", byte(fc), fc.String())
	}

	fmt.Println("\nException Codes:")
	exceptions := []layers.ModbusExceptionCode{
		layers.ModbusExceptionIllegalFunction,
		layers.ModbusExceptionIllegalDataAddress,
		layers.ModbusExceptionIllegalDataValue,
		layers.ModbusExceptionSlaveDeviceFailure,
		layers.ModbusExceptionAcknowledge,
		layers.ModbusExceptionSlaveDeviceBusy,
		layers.ModbusExceptionMemoryParityError,
		layers.ModbusExceptionGatewayPathUnavailable,
		layers.ModbusExceptionGatewayTargetDeviceFailedToRespond,
	}

	for _, exc := range exceptions {
		fmt.Printf("  0x%02X  %s\n", byte(exc), exc.String())
	}
	fmt.Println()
}
