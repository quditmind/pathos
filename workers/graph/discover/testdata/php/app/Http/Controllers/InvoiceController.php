<?php
// Example Laravel controller (test fixture for pathos-graph; not run).
namespace App\Http\Controllers;

use App\Services\Billing;

class InvoiceController
{
    public function __construct(private Billing $billing) {}

    public function show($id)
    {
        $total = $this->billing->total($id);
        return $this->render($total);
    }

    private function render($total)
    {
        return Billing::format($total);
    }
}
