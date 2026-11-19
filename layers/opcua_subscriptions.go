// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file in the root of the source tree.

// OPC UA monitored item and subscription services (OPC 10000-4 §5.12,
// §5.13).
//
//	CreateSubscription ─ subscription id
//	CreateMonitoredItems ─ client handle per item
//	Publish ─ NotificationMessage ─┬─ DataChangeNotification (handle, DataValue)
//	                               ├─ EventNotificationList  (handle, fields)
//	                               └─ StatusChangeNotification

package layers

import "time"

// Minimum encoded sizes of the subscription structures.
const (
	opcuaMinMonParamsLen  = opcuaUint32Len + opcuaUint64Len + opcuaMinExtObjLen + opcuaUint32Len + opcuaUint8Len
	opcuaMinItemCreateLen = opcuaMinReadValueIDLen + opcuaUint32Len + opcuaMinMonParamsLen
	opcuaMinItemModifyLen = opcuaUint32Len + opcuaMinMonParamsLen
	opcuaMinCreateResLen  = 2*opcuaUint32Len + opcuaUint64Len + opcuaUint32Len + opcuaMinExtObjLen
	opcuaMinModifyResLen  = opcuaUint32Len + opcuaUint64Len + opcuaUint32Len + opcuaMinExtObjLen
	opcuaMinSubAckLen     = 2 * opcuaUint32Len
	opcuaMinItemNotifLen  = opcuaUint32Len + opcuaMinMaskedLen
	opcuaMinEventListLen  = 2 * opcuaUint32Len
	opcuaMinTransferLen   = 2 * opcuaUint32Len
)

// Binary encoding ids of the notification data (NodeIds.csv).
const (
	opcuaDataChangeNotifID   = 811
	opcuaStatusChangeNotifID = 820
	opcuaEventNotifListID    = 916
)

// OPCUAMonitoringMode is a MonitoringMode (OPC 10000-4 §7.23).
type OPCUAMonitoringMode uint32

// OPCUAMonitoringMode values.
const (
	OPCUAMonitoringDisabled  OPCUAMonitoringMode = 0
	OPCUAMonitoringSampling  OPCUAMonitoringMode = 1
	OPCUAMonitoringReporting OPCUAMonitoringMode = 2
)

var opcuaMonitoringModeNames = map[OPCUAMonitoringMode]string{
	OPCUAMonitoringDisabled:  "Disabled",
	OPCUAMonitoringSampling:  "Sampling",
	OPCUAMonitoringReporting: "Reporting",
}

// String returns the mode name.
func (m OPCUAMonitoringMode) String() string { return opcuaName(opcuaMonitoringModeNames, m) }

// OPCUAMonitoringParameters are the sampling and queueing settings of a
// monitored item (OPC 10000-4 §7.21). The Value of Filter is an
// *OPCUADataChangeFilter, *OPCUAEventFilter or *OPCUAAggregateFilter.
type OPCUAMonitoringParameters struct {
	ClientHandle uint32
	// SamplingInterval is in milliseconds.
	SamplingInterval float64
	Filter           OPCUAExtensionObject
	QueueSize        uint32
	DiscardOldest    bool
}

// OPCUAMonitoredItemCreate is one item to monitor.
type OPCUAMonitoredItemCreate struct {
	ItemToMonitor       OPCUAReadValueID
	MonitoringMode      OPCUAMonitoringMode
	RequestedParameters OPCUAMonitoringParameters
}

// OPCUACreateItemsRequest is the CreateMonitoredItems request (OPC 10000-4
// §5.12.2).
type OPCUACreateItemsRequest struct {
	SubscriptionID     uint32
	TimestampsToReturn OPCUATimestampsToReturn
	ItemsToCreate      []OPCUAMonitoredItemCreate
}

// OPCUAMonitoredItemRevision is the sampling a server grants a monitored
// item. The Value of FilterResult is an *OPCUAEventFilterResult or
// *OPCUAAggregateFilterResult.
type OPCUAMonitoredItemRevision struct {
	// RevisedSamplingInterval is in milliseconds.
	RevisedSamplingInterval float64
	RevisedQueueSize        uint32
	FilterResult            OPCUAExtensionObject
}

// OPCUAMonitoredItemCreateResult is the result of creating one monitored
// item.
type OPCUAMonitoredItemCreateResult struct {
	StatusCode      OPCUAStatusCode
	MonitoredItemID uint32
	OPCUAMonitoredItemRevision
}

// OPCUACreateItemsResponse is the CreateMonitoredItems response.
type OPCUACreateItemsResponse struct {
	Results         []OPCUAMonitoredItemCreateResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAMonitoredItemModifyResult is the result of changing one monitored
// item.
type OPCUAMonitoredItemModifyResult struct {
	StatusCode OPCUAStatusCode
	OPCUAMonitoredItemRevision
}

// OPCUAModifyItemsResponse is the ModifyMonitoredItems response.
type OPCUAModifyItemsResponse struct {
	Results         []OPCUAMonitoredItemModifyResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAMonitoredItemModify is one monitored item to change.
type OPCUAMonitoredItemModify struct {
	MonitoredItemID     uint32
	RequestedParameters OPCUAMonitoringParameters
}

// OPCUAModifyItemsRequest is the ModifyMonitoredItems request
// (OPC 10000-4 §5.12.3).
type OPCUAModifyItemsRequest struct {
	SubscriptionID     uint32
	TimestampsToReturn OPCUATimestampsToReturn
	ItemsToModify      []OPCUAMonitoredItemModify
}

// OPCUASetMonitoringRequest is the SetMonitoringMode request (OPC 10000-4
// §5.12.4).
type OPCUASetMonitoringRequest struct {
	SubscriptionID   uint32
	MonitoringMode   OPCUAMonitoringMode
	MonitoredItemIDs []uint32
}

// OPCUASetTriggeringRequest is the SetTriggering request (OPC 10000-4
// §5.12.5): the items a triggering item makes report.
type OPCUASetTriggeringRequest struct {
	SubscriptionID   uint32
	TriggeringItemID uint32
	LinksToAdd       []uint32
	LinksToRemove    []uint32
}

// OPCUASetTriggeringResponse is the SetTriggering response.
type OPCUASetTriggeringResponse struct {
	AddResults            []OPCUAStatusCode
	AddDiagnosticInfos    []OPCUADiagnosticInfo
	RemoveResults         []OPCUAStatusCode
	RemoveDiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUATransferSubsRequest is the TransferSubscriptions request
// (OPC 10000-4 §5.13.7).
type OPCUATransferSubsRequest struct {
	SubscriptionIDs   []uint32
	SendInitialValues bool
}

// OPCUATransferResult is the result of moving one subscription.
type OPCUATransferResult struct {
	StatusCode               OPCUAStatusCode
	AvailableSequenceNumbers []uint32
}

// OPCUATransferSubsResponse is the TransferSubscriptions response.
type OPCUATransferSubsResponse struct {
	Results         []OPCUATransferResult
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUADeleteItemsRequest is the DeleteMonitoredItems request
// (OPC 10000-4 §5.12.6).
type OPCUADeleteItemsRequest struct {
	SubscriptionID   uint32
	MonitoredItemIDs []uint32
}

// OPCUASubscriptionParams are the timing a client asks of a
// subscription, in CreateSubscription and ModifySubscription requests.
type OPCUASubscriptionParams struct {
	// RequestedPublishingInterval is in milliseconds.
	RequestedPublishingInterval float64
	RequestedLifetimeCount      uint32
	RequestedMaxKeepAliveCount  uint32
	MaxNotificationsPerPublish  uint32
}

// OPCUACreateSubRequest is the CreateSubscription request (OPC 10000-4
// §5.13.2).
type OPCUACreateSubRequest struct {
	OPCUASubscriptionParams
	PublishingEnabled bool
	Priority          uint8
}

// OPCUAModifySubRequest is the ModifySubscription request (OPC 10000-4
// §5.13.3).
type OPCUAModifySubRequest struct {
	SubscriptionID uint32
	OPCUASubscriptionParams
	Priority uint8
}

// OPCUASubscriptionRevision is the timing a server grants, the
// ModifySubscription response.
type OPCUASubscriptionRevision struct {
	// RevisedPublishingInterval is in milliseconds.
	RevisedPublishingInterval float64
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
}

// OPCUACreateSubResponse is the CreateSubscription response.
type OPCUACreateSubResponse struct {
	SubscriptionID uint32
	OPCUASubscriptionRevision
}

// OPCUASetPublishingRequest is the SetPublishingMode request (OPC 10000-4
// §5.13.4).
type OPCUASetPublishingRequest struct {
	PublishingEnabled bool
	SubscriptionIDs   []uint32
}

// OPCUASubscriptionIDs is the DeleteSubscriptions request (OPC 10000-4
// §5.13.8).
type OPCUASubscriptionIDs struct {
	SubscriptionIDs []uint32
}

// OPCUASubscriptionAck acknowledges one notification message.
type OPCUASubscriptionAck struct {
	SubscriptionID uint32
	SequenceNumber uint32
}

// OPCUAPublishRequest is the Publish request (OPC 10000-4 §5.13.5).
type OPCUAPublishRequest struct {
	SubscriptionAcknowledgements []OPCUASubscriptionAck
}

// OPCUAMonitoredItemNotif is one changed value of a monitored item.
type OPCUAMonitoredItemNotif struct {
	ClientHandle uint32
	Value        OPCUADataValue
}

// OPCUADataChangeNotification reports changed values (OPC 10000-4
// §7.25.2).
type OPCUADataChangeNotification struct {
	MonitoredItems  []OPCUAMonitoredItemNotif
	DiagnosticInfos []OPCUADiagnosticInfo
}

// OPCUAEventFieldList is the selected fields of one event.
type OPCUAEventFieldList struct {
	ClientHandle uint32
	EventFields  []OPCUAVariant
}

// OPCUAEventNotificationList reports events (OPC 10000-4 §7.25.3).
type OPCUAEventNotificationList struct {
	Events []OPCUAEventFieldList
}

// OPCUAStatusChangeNotification reports a subscription status change
// (OPC 10000-4 §7.25.4).
type OPCUAStatusChangeNotification struct {
	Status         OPCUAStatusCode
	DiagnosticInfo OPCUADiagnosticInfo
}

// OPCUANotificationData is one entry of a NotificationMessage: the
// ExtensionObject as sent and, for the three standard notification
// types in binary form, the one decoded pointer that is set, which is
// the Value of Raw.
type OPCUANotificationData struct {
	Raw          OPCUAExtensionObject
	DataChange   *OPCUADataChangeNotification
	Events       *OPCUAEventNotificationList
	StatusChange *OPCUAStatusChangeNotification
}

// OPCUANotificationMessage is a NotificationMessage (OPC 10000-4 §7.24).
type OPCUANotificationMessage struct {
	SequenceNumber   uint32
	PublishTime      time.Time
	NotificationData []OPCUANotificationData
}

// OPCUAPublishResponse is the Publish response.
type OPCUAPublishResponse struct {
	SubscriptionID           uint32
	AvailableSequenceNumbers []uint32
	MoreNotifications        bool
	NotificationMessage      OPCUANotificationMessage
	OPCUAResults
}

// OPCUARepublishRequest is the Republish request (OPC 10000-4 §5.13.6).
type OPCUARepublishRequest struct {
	SubscriptionID           uint32
	RetransmitSequenceNumber uint32
}

// OPCUARepublishResponse is the Republish response.
type OPCUARepublishResponse struct {
	NotificationMessage OPCUANotificationMessage
}

func (r *opcuaReader) readValueID() OPCUAReadValueID {
	return OPCUAReadValueID{
		NodeID:       r.nodeID(),
		AttributeID:  OPCUAAttributeID(r.u32()),
		IndexRange:   r.str(),
		DataEncoding: r.qualifiedName(),
	}
}

func (r *opcuaReader) monitoringParams() OPCUAMonitoringParameters {
	return OPCUAMonitoringParameters{
		ClientHandle:     r.u32(),
		SamplingInterval: r.f64(),
		Filter:           r.extensionObject(),
		QueueSize:        r.u32(),
		DiscardOldest:    r.boolean(),
	}
}

func (r *opcuaReader) createItemsRequest() *OPCUACreateItemsRequest {
	return &OPCUACreateItemsRequest{
		SubscriptionID:     r.u32(),
		TimestampsToReturn: OPCUATimestampsToReturn(r.u32()),
		ItemsToCreate:      opcuaArray(r, opcuaMinItemCreateLen, r.itemCreate),
	}
}

func (r *opcuaReader) itemCreate() OPCUAMonitoredItemCreate {
	return OPCUAMonitoredItemCreate{
		ItemToMonitor:       r.readValueID(),
		MonitoringMode:      OPCUAMonitoringMode(r.u32()),
		RequestedParameters: r.monitoringParams(),
	}
}

func (r *opcuaReader) itemRevision() OPCUAMonitoredItemRevision {
	return OPCUAMonitoredItemRevision{
		RevisedSamplingInterval: r.f64(),
		RevisedQueueSize:        r.u32(),
		FilterResult:            r.extensionObject(),
	}
}

func (r *opcuaReader) createItemsResponse() *OPCUACreateItemsResponse {
	results := opcuaArray(r, opcuaMinCreateResLen, func() OPCUAMonitoredItemCreateResult {
		return OPCUAMonitoredItemCreateResult{
			StatusCode:                 r.statusCode(),
			MonitoredItemID:            r.u32(),
			OPCUAMonitoredItemRevision: r.itemRevision(),
		}
	})
	return &OPCUACreateItemsResponse{Results: results, DiagnosticInfos: r.diagnosticInfos()}
}

func (r *opcuaReader) modifyItemsResponse() *OPCUAModifyItemsResponse {
	results := opcuaArray(r, opcuaMinModifyResLen, func() OPCUAMonitoredItemModifyResult {
		return OPCUAMonitoredItemModifyResult{StatusCode: r.statusCode(), OPCUAMonitoredItemRevision: r.itemRevision()}
	})
	return &OPCUAModifyItemsResponse{Results: results, DiagnosticInfos: r.diagnosticInfos()}
}

func (r *opcuaReader) modifyItemsRequest() *OPCUAModifyItemsRequest {
	return &OPCUAModifyItemsRequest{
		SubscriptionID:     r.u32(),
		TimestampsToReturn: OPCUATimestampsToReturn(r.u32()),
		ItemsToModify: opcuaArray(r, opcuaMinItemModifyLen, func() OPCUAMonitoredItemModify {
			return OPCUAMonitoredItemModify{MonitoredItemID: r.u32(), RequestedParameters: r.monitoringParams()}
		}),
	}
}

func (r *opcuaReader) setMonitoringRequest() *OPCUASetMonitoringRequest {
	return &OPCUASetMonitoringRequest{
		SubscriptionID:   r.u32(),
		MonitoringMode:   OPCUAMonitoringMode(r.u32()),
		MonitoredItemIDs: r.u32s(),
	}
}

func (r *opcuaReader) deleteItemsRequest() *OPCUADeleteItemsRequest {
	return &OPCUADeleteItemsRequest{SubscriptionID: r.u32(), MonitoredItemIDs: r.u32s()}
}

func (r *opcuaReader) subParams() OPCUASubscriptionParams {
	return OPCUASubscriptionParams{
		RequestedPublishingInterval: r.f64(),
		RequestedLifetimeCount:      r.u32(),
		RequestedMaxKeepAliveCount:  r.u32(),
		MaxNotificationsPerPublish:  r.u32(),
	}
}

func (r *opcuaReader) subRevision() OPCUASubscriptionRevision {
	return OPCUASubscriptionRevision{
		RevisedPublishingInterval: r.f64(),
		RevisedLifetimeCount:      r.u32(),
		RevisedMaxKeepAliveCount:  r.u32(),
	}
}

func (r *opcuaReader) createSubRequest() *OPCUACreateSubRequest {
	return &OPCUACreateSubRequest{OPCUASubscriptionParams: r.subParams(), PublishingEnabled: r.boolean(), Priority: r.u8()}
}

func (r *opcuaReader) modifySubRequest() *OPCUAModifySubRequest {
	return &OPCUAModifySubRequest{SubscriptionID: r.u32(), OPCUASubscriptionParams: r.subParams(), Priority: r.u8()}
}

func (r *opcuaReader) createSubResponse() *OPCUACreateSubResponse {
	return &OPCUACreateSubResponse{SubscriptionID: r.u32(), OPCUASubscriptionRevision: r.subRevision()}
}

func (r *opcuaReader) modifySubResponse() *OPCUASubscriptionRevision {
	rev := r.subRevision()
	return &rev
}

func (r *opcuaReader) setPublishingRequest() *OPCUASetPublishingRequest {
	return &OPCUASetPublishingRequest{PublishingEnabled: r.boolean(), SubscriptionIDs: r.u32s()}
}

func (r *opcuaReader) publishRequest() *OPCUAPublishRequest {
	return &OPCUAPublishRequest{SubscriptionAcknowledgements: opcuaArray(r, opcuaMinSubAckLen, func() OPCUASubscriptionAck {
		return OPCUASubscriptionAck{SubscriptionID: r.u32(), SequenceNumber: r.u32()}
	})}
}

func (r *opcuaReader) publishResponse() *OPCUAPublishResponse {
	return &OPCUAPublishResponse{
		SubscriptionID:           r.u32(),
		AvailableSequenceNumbers: r.u32s(),
		MoreNotifications:        r.boolean(),
		NotificationMessage:      r.notificationMessage(),
		OPCUAResults:             r.results(),
	}
}

func (r *opcuaReader) republishRequest() *OPCUARepublishRequest {
	return &OPCUARepublishRequest{SubscriptionID: r.u32(), RetransmitSequenceNumber: r.u32()}
}

func (r *opcuaReader) republishResponse() *OPCUARepublishResponse {
	return &OPCUARepublishResponse{NotificationMessage: r.notificationMessage()}
}

// notificationMessage reads a NotificationMessage and decodes the
// standard notifications it carries.
func (r *opcuaReader) notificationMessage() OPCUANotificationMessage {
	m := OPCUANotificationMessage{SequenceNumber: r.u32(), PublishTime: r.dateTime()}
	m.NotificationData = opcuaArray(r, opcuaMinExtObjLen, func() OPCUANotificationData {
		return decodeNotification(r.extensionObject())
	})
	return m
}

// decodeNotification sorts a notification ExtensionObject by the type
// of its decoded Value. A body that does not parse leaves only Raw set,
// as for an unknown type.
func decodeNotification(e OPCUAExtensionObject) OPCUANotificationData {
	n := OPCUANotificationData{Raw: e}
	switch v := e.Value.(type) {
	case *OPCUADataChangeNotification:
		n.DataChange = v
	case *OPCUAEventNotificationList:
		n.Events = v
	case *OPCUAStatusChangeNotification:
		n.StatusChange = v
	}
	return n
}

func (r *opcuaReader) setTriggeringRequest() *OPCUASetTriggeringRequest {
	return &OPCUASetTriggeringRequest{
		SubscriptionID:   r.u32(),
		TriggeringItemID: r.u32(),
		LinksToAdd:       r.u32s(),
		LinksToRemove:    r.u32s(),
	}
}

func (r *opcuaReader) setTriggeringResponse() *OPCUASetTriggeringResponse {
	return &OPCUASetTriggeringResponse{
		AddResults:            r.statusCodes(),
		AddDiagnosticInfos:    r.diagnosticInfos(),
		RemoveResults:         r.statusCodes(),
		RemoveDiagnosticInfos: r.diagnosticInfos(),
	}
}

func (r *opcuaReader) transferSubsResponse() *OPCUATransferSubsResponse {
	return &OPCUATransferSubsResponse{
		Results: opcuaArray(r, opcuaMinTransferLen, func() OPCUATransferResult {
			return OPCUATransferResult{StatusCode: r.statusCode(), AvailableSequenceNumbers: r.u32s()}
		}),
		DiagnosticInfos: r.diagnosticInfos(),
	}
}
