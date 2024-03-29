// Code generated by go-swagger; DO NOT EDIT.

package statements

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

// NewGetStatementsParams creates a new GetStatementsParams object
// with the default values initialized.
func NewGetStatementsParams() *GetStatementsParams {
	var ()
	return &GetStatementsParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetStatementsParamsWithTimeout creates a new GetStatementsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetStatementsParamsWithTimeout(timeout time.Duration) *GetStatementsParams {
	var ()
	return &GetStatementsParams{

		timeout: timeout,
	}
}

// NewGetStatementsParamsWithContext creates a new GetStatementsParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetStatementsParamsWithContext(ctx context.Context) *GetStatementsParams {
	var ()
	return &GetStatementsParams{

		Context: ctx,
	}
}

// NewGetStatementsParamsWithHTTPClient creates a new GetStatementsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetStatementsParamsWithHTTPClient(client *http.Client) *GetStatementsParams {
	var ()
	return &GetStatementsParams{
		HTTPClient: client,
	}
}

/*GetStatementsParams contains all the parameters to send to the API endpoint
for the get statements operation typically these are written to a http.Request
*/
type GetStatementsParams struct {

	/*AccountID
	  accountId

	*/
	AccountID *string
	/*Container
	  creditCard/loan/bill/insurance

	*/
	Container *string
	/*FromDate
	  from date for statement retrieval (YYYY-MM-DD)

	*/
	FromDate *string
	/*IsLatest
	  isLatest (true/false)

	*/
	IsLatest *string
	/*Status
	  ACTIVE/TO_BE_CLOSED/CLOSED

	*/
	Status *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get statements params
func (o *GetStatementsParams) WithTimeout(timeout time.Duration) *GetStatementsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get statements params
func (o *GetStatementsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get statements params
func (o *GetStatementsParams) WithContext(ctx context.Context) *GetStatementsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get statements params
func (o *GetStatementsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get statements params
func (o *GetStatementsParams) WithHTTPClient(client *http.Client) *GetStatementsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get statements params
func (o *GetStatementsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAccountID adds the accountID to the get statements params
func (o *GetStatementsParams) WithAccountID(accountID *string) *GetStatementsParams {
	o.SetAccountID(accountID)
	return o
}

// SetAccountID adds the accountId to the get statements params
func (o *GetStatementsParams) SetAccountID(accountID *string) {
	o.AccountID = accountID
}

// WithContainer adds the container to the get statements params
func (o *GetStatementsParams) WithContainer(container *string) *GetStatementsParams {
	o.SetContainer(container)
	return o
}

// SetContainer adds the container to the get statements params
func (o *GetStatementsParams) SetContainer(container *string) {
	o.Container = container
}

// WithFromDate adds the fromDate to the get statements params
func (o *GetStatementsParams) WithFromDate(fromDate *string) *GetStatementsParams {
	o.SetFromDate(fromDate)
	return o
}

// SetFromDate adds the fromDate to the get statements params
func (o *GetStatementsParams) SetFromDate(fromDate *string) {
	o.FromDate = fromDate
}

// WithIsLatest adds the isLatest to the get statements params
func (o *GetStatementsParams) WithIsLatest(isLatest *string) *GetStatementsParams {
	o.SetIsLatest(isLatest)
	return o
}

// SetIsLatest adds the isLatest to the get statements params
func (o *GetStatementsParams) SetIsLatest(isLatest *string) {
	o.IsLatest = isLatest
}

// WithStatus adds the status to the get statements params
func (o *GetStatementsParams) WithStatus(status *string) *GetStatementsParams {
	o.SetStatus(status)
	return o
}

// SetStatus adds the status to the get statements params
func (o *GetStatementsParams) SetStatus(status *string) {
	o.Status = status
}

// WriteToRequest writes these params to a swagger request
func (o *GetStatementsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AccountID != nil {

		// query param accountId
		var qrAccountID string
		if o.AccountID != nil {
			qrAccountID = *o.AccountID
		}
		qAccountID := qrAccountID
		if qAccountID != "" {
			if err := r.SetQueryParam("accountId", qAccountID); err != nil {
				return err
			}
		}

	}

	if o.Container != nil {

		// query param container
		var qrContainer string
		if o.Container != nil {
			qrContainer = *o.Container
		}
		qContainer := qrContainer
		if qContainer != "" {
			if err := r.SetQueryParam("container", qContainer); err != nil {
				return err
			}
		}

	}

	if o.FromDate != nil {

		// query param fromDate
		var qrFromDate string
		if o.FromDate != nil {
			qrFromDate = *o.FromDate
		}
		qFromDate := qrFromDate
		if qFromDate != "" {
			if err := r.SetQueryParam("fromDate", qFromDate); err != nil {
				return err
			}
		}

	}

	if o.IsLatest != nil {

		// query param isLatest
		var qrIsLatest string
		if o.IsLatest != nil {
			qrIsLatest = *o.IsLatest
		}
		qIsLatest := qrIsLatest
		if qIsLatest != "" {
			if err := r.SetQueryParam("isLatest", qIsLatest); err != nil {
				return err
			}
		}

	}

	if o.Status != nil {

		// query param status
		var qrStatus string
		if o.Status != nil {
			qrStatus = *o.Status
		}
		qStatus := qrStatus
		if qStatus != "" {
			if err := r.SetQueryParam("status", qStatus); err != nil {
				return err
			}
		}

	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
