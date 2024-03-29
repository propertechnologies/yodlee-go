// Code generated by go-swagger; DO NOT EDIT.

package provider_accounts

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/swag"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/propertechnologies/yodlee-go/models"
)

// NewLinkProviderAccountParams creates a new LinkProviderAccountParams object
// with the default values initialized.
func NewLinkProviderAccountParams() *LinkProviderAccountParams {
	var ()
	return &LinkProviderAccountParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewLinkProviderAccountParamsWithTimeout creates a new LinkProviderAccountParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewLinkProviderAccountParamsWithTimeout(timeout time.Duration) *LinkProviderAccountParams {
	var ()
	return &LinkProviderAccountParams{

		timeout: timeout,
	}
}

// NewLinkProviderAccountParamsWithContext creates a new LinkProviderAccountParams object
// with the default values initialized, and the ability to set a context for a request
func NewLinkProviderAccountParamsWithContext(ctx context.Context) *LinkProviderAccountParams {
	var ()
	return &LinkProviderAccountParams{

		Context: ctx,
	}
}

// NewLinkProviderAccountParamsWithHTTPClient creates a new LinkProviderAccountParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewLinkProviderAccountParamsWithHTTPClient(client *http.Client) *LinkProviderAccountParams {
	var ()
	return &LinkProviderAccountParams{
		HTTPClient: client,
	}
}

/*LinkProviderAccountParams contains all the parameters to send to the API endpoint
for the link provider account operation typically these are written to a http.Request
*/
type LinkProviderAccountParams struct {

	/*ProviderAccountRequest
	  loginForm or field entity

	*/
	ProviderAccountRequest *models.ProviderAccountRequest
	/*ProviderID
	  providerId

	*/
	ProviderID int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the link provider account params
func (o *LinkProviderAccountParams) WithTimeout(timeout time.Duration) *LinkProviderAccountParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the link provider account params
func (o *LinkProviderAccountParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the link provider account params
func (o *LinkProviderAccountParams) WithContext(ctx context.Context) *LinkProviderAccountParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the link provider account params
func (o *LinkProviderAccountParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the link provider account params
func (o *LinkProviderAccountParams) WithHTTPClient(client *http.Client) *LinkProviderAccountParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the link provider account params
func (o *LinkProviderAccountParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithProviderAccountRequest adds the providerAccountRequest to the link provider account params
func (o *LinkProviderAccountParams) WithProviderAccountRequest(providerAccountRequest *models.ProviderAccountRequest) *LinkProviderAccountParams {
	o.SetProviderAccountRequest(providerAccountRequest)
	return o
}

// SetProviderAccountRequest adds the providerAccountRequest to the link provider account params
func (o *LinkProviderAccountParams) SetProviderAccountRequest(providerAccountRequest *models.ProviderAccountRequest) {
	o.ProviderAccountRequest = providerAccountRequest
}

// WithProviderID adds the providerID to the link provider account params
func (o *LinkProviderAccountParams) WithProviderID(providerID int64) *LinkProviderAccountParams {
	o.SetProviderID(providerID)
	return o
}

// SetProviderID adds the providerId to the link provider account params
func (o *LinkProviderAccountParams) SetProviderID(providerID int64) {
	o.ProviderID = providerID
}

// WriteToRequest writes these params to a swagger request
func (o *LinkProviderAccountParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ProviderAccountRequest != nil {
		if err := r.SetBodyParam(o.ProviderAccountRequest); err != nil {
			return err
		}
	}

	// query param providerId
	qrProviderID := o.ProviderID
	qProviderID := swag.FormatInt64(qrProviderID)
	if qProviderID != "" {
		if err := r.SetQueryParam("providerId", qProviderID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
