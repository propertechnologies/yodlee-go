// Code generated by go-swagger; DO NOT EDIT.

package cobrand

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"
)

// New creates a new cobrand API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Client {
	return &Client{transport: transport, formats: formats}
}

/*
Client for cobrand API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

/*
CobrandLogin cobrands login

The cobrand login service authenticates a cobrand.<br>Cobrand session in the response includes the cobrand session token (cobSession) <br>which is used in subsequent API calls like registering or signing in the user. <br>The idle timeout for a cobrand session is 2 hours and the absolute timeout is 24 hours. This service can be <br>invoked to create a new cobrand session token. <br><b>Note:</b> This endpoint is deprecated for customers using the API Key-based authentication and is applicable only to customers who use the SAML-based authentication.<br>The content type has to be passed as application/json for the body parameter. <br>
*/
func (a *Client) CobrandLogin(params *CobrandLoginParams) (*CobrandLoginOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCobrandLoginParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "cobrandLogin",
		Method:             "POST",
		PathPattern:        "/cobrand/login",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &CobrandLoginReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CobrandLoginOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for cobrandLogin: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CobrandLogout cobrands logout

The cobrand logout service is used to log out the cobrand.<br>This service does not return a response. The HTTP response code is 204 (Success with no content).<br><b>Note:</b> This endpoint is deprecated for customers using the API Key-based authentication and is applicable only to customers who use the SAML-based authentication.<br>
*/
func (a *Client) CobrandLogout(params *CobrandLogoutParams) (*CobrandLogoutNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCobrandLogoutParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "cobrandLogout",
		Method:             "POST",
		PathPattern:        "/cobrand/logout",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &CobrandLogoutReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CobrandLogoutNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for cobrandLogout: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateSubscriptionEvent subscribes event

The subscribe events service is used to subscribe to an event for receiving notifications.<br>The callback URL, where the notification will be posted should be provided to this service.<br>Customers can subscribe to REFRESH,DATA_UPDATES and AUTO_REFRESH_UPDATES event.<br><br><b>Notes</b>:<br>This service is not available in developer sandbox/test environment and will be made available for testing in your dedicated environment, once the contract is signed.<br>The content type has to be passed as application/json for the body parameter.<br>
*/
func (a *Client) CreateSubscriptionEvent(params *CreateSubscriptionEventParams) (*CreateSubscriptionEventCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateSubscriptionEventParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createSubscriptionEvent",
		Method:             "POST",
		PathPattern:        "/cobrand/config/notifications/events/{eventName}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &CreateSubscriptionEventReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateSubscriptionEventCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createSubscriptionEvent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteSubscribedEvent deletes subscription

The delete events service is used to unsubscribe from an events service.<br>
*/
func (a *Client) DeleteSubscribedEvent(params *DeleteSubscribedEventParams) (*DeleteSubscribedEventNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteSubscribedEventParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteSubscribedEvent",
		Method:             "DELETE",
		PathPattern:        "/cobrand/config/notifications/events/{eventName}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{""},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &DeleteSubscribedEventReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteSubscribedEventNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteSubscribedEvent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetPublicKey gets public key

The get public key service provides the customer the public key that should be used to encrypt the user credentials before sending it to Yodlee.<br>This endpoint is useful only for PKI enabled.<br>
*/
func (a *Client) GetPublicKey(params *GetPublicKeyParams) (*GetPublicKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPublicKeyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getPublicKey",
		Method:             "GET",
		PathPattern:        "/cobrand/publicKey",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{""},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetPublicKeyReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetPublicKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getPublicKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSubscribedEvents gets subscribed events

The get events service provides the list of events for which consumers subscribed <br>to receive notifications. <br>
*/
func (a *Client) GetSubscribedEvents(params *GetSubscribedEventsParams) (*GetSubscribedEventsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSubscribedEventsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getSubscribedEvents",
		Method:             "GET",
		PathPattern:        "/cobrand/config/notifications/events",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{""},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &GetSubscribedEventsReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetSubscribedEventsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getSubscribedEvents: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateSubscribedEvent updates subscription

The update events service is used to update the callback URL.<br><b>Note:</b> The content type has to be passed as application/json for the body parameter. <br>
*/
func (a *Client) UpdateSubscribedEvent(params *UpdateSubscribedEventParams) (*UpdateSubscribedEventNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateSubscribedEventParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "updateSubscribedEvent",
		Method:             "PUT",
		PathPattern:        "/cobrand/config/notifications/events/{eventName}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http"},
		Params:             params,
		Reader:             &UpdateSubscribedEventReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdateSubscribedEventNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateSubscribedEvent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}