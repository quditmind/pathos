package io.github.quditmind.pathos.ui

import com.intellij.ui.ColoredListCellRenderer
import javax.swing.JList

/**
 * List renderer showing [text] of each item. SimpleColoredComponent never
 * interprets HTML, so untrusted text is always shown as plain text.
 */
fun <T> plainTextRenderer(text: (T) -> String): ColoredListCellRenderer<T> = object : ColoredListCellRenderer<T>() {
    override fun customizeCellRenderer(list: JList<out T>, value: T?, index: Int, selected: Boolean, hasFocus: Boolean) {
        if (value != null) append(text(value))
    }
}
