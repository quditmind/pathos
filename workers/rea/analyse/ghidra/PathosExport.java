// PATHOS reverse engineering: Ghidra headless post-script (run by
// pathos-rea with -postScript PathosExport.java <out.json> <offsets.txt>).
// Writes the functions, the call graph and the decompiled pseudo-C of the
// functions listed in offsets.txt (file offsets, one per line) as JSON.
// Every address is reported as a file offset, so pathos-rea can match it
// with the other tools whatever base address Ghidra chose.
// @category PATHOS
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

public class PathosExport extends GhidraScript {
    private long off(Address a) {
        if (a == null) return -1;
        ghidra.program.model.mem.MemoryBlock b = currentProgram.getMemory().getBlock(a);
        if (b == null) return -1;
        for (MemoryBlockSourceInfo si : b.getSourceInfos()) {
            if (si.contains(a)) {
                long fo = si.getFileBytesOffset(a);
                if (fo >= 0) return fo;
            }
        }
        return -1;
    }

    private static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Set<Long> wanted = new HashSet<>();
        for (String l : Files.readAllLines(Paths.get(args[1]), StandardCharsets.UTF_8)) {
            l = l.trim();
            if (!l.isEmpty()) wanted.add(Long.parseLong(l));
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(Paths.get(args[0]), StandardCharsets.UTF_8))) {
            StringBuilder fns = new StringBuilder(), calls = new StringBuilder(), code = new StringBuilder();
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int nf = 0, nc = 0, nd = 0;
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal() || f.isThunk()) continue;
                long fo = off(f.getEntryPoint());
                if (fo < 0) continue;
                if (nf++ > 0) fns.append(',');
                fns.append("{\"name\":").append(q(f.getName(true))).append(",\"entry\":\"").append(fo)
                   .append("\",\"size\":").append(f.getBody().getNumAddresses()).append('}');
                if (nc < 100000) {
                    for (Function callee : f.getCalledFunctions(monitor)) {
                        long co = off(callee.getEntryPoint());
                        if (co < 0) continue;
                        if (nc++ > 0) calls.append(',');
                        calls.append("{\"from\":\"").append(fo).append("\",\"to\":\"").append(co).append("\",\"at\":\"\"}");
                    }
                }
                if (wanted.contains(fo)) {
                    DecompileResults r = dec.decompileFunction(f, 60, monitor);
                    if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        if (nd++ > 0) code.append(',');
                        code.append("{\"entry\":\"").append(fo).append("\",\"text\":").append(q(r.getDecompiledFunction().getC())).append('}');
                    }
                }
            }
            w.print("{\"functions\":[" + fns + "],\"calls\":[" + calls + "],\"code\":[" + code + "]}");
        } finally {
            dec.dispose();
        }
    }
}
