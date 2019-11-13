// Code generated by go-swagger; DO NOT EDIT.

package cobrand

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// NewUpdateSubscribedEventParams creates a new UpdateSubscribedEventParams object
// with the default values initialized.
func NewUpdateSubscribedEventParams() *UpdateSubscribedEventParams {
	var ()
	return &UpdateSubscribedEventParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateSubscribedEventParamsWithTimeout creates a new UpdateSubscribedEventParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdateSubscribedEventParamsWithTimeout(timeout time.Duration) *UpdateSubscribedEventParams {
	var ()
	return &UpdateSubscribedEventParams{

		timeout: timeout,
	}
}

// NewUpdateSubscribedEventParamsWithContext creates a new UpdateSubscribedEventParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdateSubscribedEventParamsWithContext(ctx context.Context) *UpdateSubscribedEventParams {
	var ()
	return &UpdateSubscribedEventParams{

		Context: ctx,
	}
}

// NewUpdateSubscribedEventParamsWithHTTPClient creates a new UpdateSubscribedEventParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdateSubscribedEventParamsWithHTTPClient(client *http.Client) *UpdateSubscribedEventParams {
	var ()
	return &UpdateSubscribedEventParams{
		HTTPClient: client,
	}
}

/*UpdateSubscribedEventParams contains all the parameters to send to the API endpoint
for the update subscribed event operation typically these are written to a http.Request
*/
type UpdateSubscribedEventParams struct {

	/*EventName
	  eventName

	*/
	EventName string
	/*EventRequest
	  eventRequest

	*/
	EventRequest *models.UpdateCobrandNotificationEventRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the update subscribed event params
func (o *UpdateSubscribedEventParams) WithTimeout(timeout time.Duration) *UpdateSubscribedEventParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update subscribed event params
func (o *UpdateSubscribedEventParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update subscribed event params
func (o *UpdateSubscribedEventParams) WithContext(ctx context.Context) *UpdateSubscribedEventParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update subscribed event params
func (o *UpdateSubscribedEventParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update subscribed event params
func (o *UpdateSubscribedEventParams) WithHTTPClient(client *http.Client) *UpdateSubscribedEventParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update subscribed event params
func (o *UpdateSubscribedEventParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEventName adds the eventName to the update subscribed event params
func (o *UpdateSubscribedEventParams) WithEventName(eventName string) *UpdateSubscribedEventParams {
	o.SetEventName(eventName)
	return o
}

// SetEventName adds the eventName to the update subscribed event params
func (o *UpdateSubscribedEventParams) SetEventName(eventName string) {
	o.EventName = eventName
}

// WithEventRequest adds the eventRequest to the update subscribed event params
func (o *UpdateSubscribedEventParams) WithEventRequest(eventRequest *models.UpdateCobrandNotificationEventRequest) *UpdateSubscribedEventParams {
	o.SetEventRequest(eventRequest)
	return o
}

// SetEventRequest adds the eventRequest to the update subscribed event params
func (o *UpdateSubscribedEventParams) SetEventRequest(eventRequest *models.UpdateCobrandNotificationEventRequest) {
	o.EventRequest = eventRequest
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateSubscribedEventParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param eventName
	if err := r.SetPathParam("eventName", o.EventName); err != nil {
		return err
	}

	if o.EventRequest != nil {
		if err := r.SetBodyParam(o.EventRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
