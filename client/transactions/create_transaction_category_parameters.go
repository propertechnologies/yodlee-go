// Code generated by go-swagger; DO NOT EDIT.

package transactions

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

	models "yodlee-golang-client/models"
)

// NewCreateTransactionCategoryParams creates a new CreateTransactionCategoryParams object
// with the default values initialized.
func NewCreateTransactionCategoryParams() *CreateTransactionCategoryParams {
	var ()
	return &CreateTransactionCategoryParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewCreateTransactionCategoryParamsWithTimeout creates a new CreateTransactionCategoryParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCreateTransactionCategoryParamsWithTimeout(timeout time.Duration) *CreateTransactionCategoryParams {
	var ()
	return &CreateTransactionCategoryParams{

		timeout: timeout,
	}
}

// NewCreateTransactionCategoryParamsWithContext creates a new CreateTransactionCategoryParams object
// with the default values initialized, and the ability to set a context for a request
func NewCreateTransactionCategoryParamsWithContext(ctx context.Context) *CreateTransactionCategoryParams {
	var ()
	return &CreateTransactionCategoryParams{

		Context: ctx,
	}
}

// NewCreateTransactionCategoryParamsWithHTTPClient creates a new CreateTransactionCategoryParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCreateTransactionCategoryParamsWithHTTPClient(client *http.Client) *CreateTransactionCategoryParams {
	var ()
	return &CreateTransactionCategoryParams{
		HTTPClient: client,
	}
}

/*CreateTransactionCategoryParams contains all the parameters to send to the API endpoint
for the create transaction category operation typically these are written to a http.Request
*/
type CreateTransactionCategoryParams struct {

	/*TransactionCategoryRequest
	  User Transaction Category in JSON format

	*/
	TransactionCategoryRequest *models.TransactionCategoryRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the create transaction category params
func (o *CreateTransactionCategoryParams) WithTimeout(timeout time.Duration) *CreateTransactionCategoryParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create transaction category params
func (o *CreateTransactionCategoryParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create transaction category params
func (o *CreateTransactionCategoryParams) WithContext(ctx context.Context) *CreateTransactionCategoryParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create transaction category params
func (o *CreateTransactionCategoryParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create transaction category params
func (o *CreateTransactionCategoryParams) WithHTTPClient(client *http.Client) *CreateTransactionCategoryParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create transaction category params
func (o *CreateTransactionCategoryParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTransactionCategoryRequest adds the transactionCategoryRequest to the create transaction category params
func (o *CreateTransactionCategoryParams) WithTransactionCategoryRequest(transactionCategoryRequest *models.TransactionCategoryRequest) *CreateTransactionCategoryParams {
	o.SetTransactionCategoryRequest(transactionCategoryRequest)
	return o
}

// SetTransactionCategoryRequest adds the transactionCategoryRequest to the create transaction category params
func (o *CreateTransactionCategoryParams) SetTransactionCategoryRequest(transactionCategoryRequest *models.TransactionCategoryRequest) {
	o.TransactionCategoryRequest = transactionCategoryRequest
}

// WriteToRequest writes these params to a swagger request
func (o *CreateTransactionCategoryParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.TransactionCategoryRequest != nil {
		if err := r.SetBodyParam(o.TransactionCategoryRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}