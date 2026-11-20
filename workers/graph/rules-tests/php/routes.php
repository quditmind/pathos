<?php
// Test fixture for the PATHOS graph rules (example code, not executed).
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;
use App\Models\Invoice;

// ruleid: pathos-graph-php-route-laravel
Route::get('/invoices/{id}', 'InvoiceController@show');
// ruleid: pathos-graph-php-route-laravel
Route::post('/invoices', [InvoiceController::class, 'store']);

function totals() {
    // ruleid: pathos-graph-php-db-facade-read
    $rows = DB::select('SELECT sum(amount) FROM invoices');
    // ruleid: pathos-graph-php-db-eloquent
    $open = Invoice::where('status', 'open');
    // ruleid: pathos-graph-php-queue-dispatch
    dispatch(new SendInvoice($open));
    // ruleid: pathos-graph-php-http-call
    Http::post('https://api.mailer.example.net/send', []);
    return $rows;
}
