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

// NewUpdatePreferencesParams creates a new UpdatePreferencesParams object
// with the default values initialized.
func NewUpdatePreferencesParams() *UpdatePreferencesParams {
	var ()
	return &UpdatePreferencesParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdatePreferencesParamsWithTimeout creates a new UpdatePreferencesParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdatePreferencesParamsWithTimeout(timeout time.Duration) *UpdatePreferencesParams {
	var ()
	return &UpdatePreferencesParams{

		timeout: timeout,
	}
}

// NewUpdatePreferencesParamsWithContext creates a new UpdatePreferencesParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdatePreferencesParamsWithContext(ctx context.Context) *UpdatePreferencesParams {
	var ()
	return &UpdatePreferencesParams{

		Context: ctx,
	}
}

// NewUpdatePreferencesParamsWithHTTPClient creates a new UpdatePreferencesParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdatePreferencesParamsWithHTTPClient(client *http.Client) *UpdatePreferencesParams {
	var ()
	return &UpdatePreferencesParams{
		HTTPClient: client,
	}
}

/*UpdatePreferencesParams contains all the parameters to send to the API endpoint
for the update preferences operation typically these are written to a http.Request
*/
type UpdatePreferencesParams struct {

	/*Preferences
	  preferences

	*/
	Preferences *models.ProviderAccountPreferencesRequest
	/*ProviderAccountID
	  providerAccountId

	*/
	ProviderAccountID int64

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the update preferences params
func (o *UpdatePreferencesParams) WithTimeout(timeout time.Duration) *UpdatePreferencesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update preferences params
func (o *UpdatePreferencesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update preferences params
func (o *UpdatePreferencesParams) WithContext(ctx context.Context) *UpdatePreferencesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update preferences params
func (o *UpdatePreferencesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update preferences params
func (o *UpdatePreferencesParams) WithHTTPClient(client *http.Client) *UpdatePreferencesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update preferences params
func (o *UpdatePreferencesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPreferences adds the preferences to the update preferences params
func (o *UpdatePreferencesParams) WithPreferences(preferences *models.ProviderAccountPreferencesRequest) *UpdatePreferencesParams {
	o.SetPreferences(preferences)
	return o
}

// SetPreferences adds the preferences to the update preferences params
func (o *UpdatePreferencesParams) SetPreferences(preferences *models.ProviderAccountPreferencesRequest) {
	o.Preferences = preferences
}

// WithProviderAccountID adds the providerAccountID to the update preferences params
func (o *UpdatePreferencesParams) WithProviderAccountID(providerAccountID int64) *UpdatePreferencesParams {
	o.SetProviderAccountID(providerAccountID)
	return o
}

// SetProviderAccountID adds the providerAccountId to the update preferences params
func (o *UpdatePreferencesParams) SetProviderAccountID(providerAccountID int64) {
	o.ProviderAccountID = providerAccountID
}

// WriteToRequest writes these params to a swagger request
func (o *UpdatePreferencesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Preferences != nil {
		if err := r.SetBodyParam(o.Preferences); err != nil {
			return err
		}
	}

	// path param providerAccountId
	if err := r.SetPathParam("providerAccountId", swag.FormatInt64(o.ProviderAccountID)); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
