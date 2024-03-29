// Code generated by go-swagger; DO NOT EDIT.

package holdings

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
)

// NewGetAssetClassificationListParams creates a new GetAssetClassificationListParams object
// with the default values initialized.
func NewGetAssetClassificationListParams() *GetAssetClassificationListParams {

	return &GetAssetClassificationListParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetAssetClassificationListParamsWithTimeout creates a new GetAssetClassificationListParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetAssetClassificationListParamsWithTimeout(timeout time.Duration) *GetAssetClassificationListParams {

	return &GetAssetClassificationListParams{

		timeout: timeout,
	}
}

// NewGetAssetClassificationListParamsWithContext creates a new GetAssetClassificationListParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetAssetClassificationListParamsWithContext(ctx context.Context) *GetAssetClassificationListParams {

	return &GetAssetClassificationListParams{

		Context: ctx,
	}
}

// NewGetAssetClassificationListParamsWithHTTPClient creates a new GetAssetClassificationListParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetAssetClassificationListParamsWithHTTPClient(client *http.Client) *GetAssetClassificationListParams {

	return &GetAssetClassificationListParams{
		HTTPClient: client,
	}
}

/*GetAssetClassificationListParams contains all the parameters to send to the API endpoint
for the get asset classification list operation typically these are written to a http.Request
*/
type GetAssetClassificationListParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get asset classification list params
func (o *GetAssetClassificationListParams) WithTimeout(timeout time.Duration) *GetAssetClassificationListParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get asset classification list params
func (o *GetAssetClassificationListParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get asset classification list params
func (o *GetAssetClassificationListParams) WithContext(ctx context.Context) *GetAssetClassificationListParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get asset classification list params
func (o *GetAssetClassificationListParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get asset classification list params
func (o *GetAssetClassificationListParams) WithHTTPClient(client *http.Client) *GetAssetClassificationListParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get asset classification list params
func (o *GetAssetClassificationListParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetAssetClassificationListParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
