package org.friendlypass.android.autofill

import android.app.assist.AssistStructure
import android.app.assist.AssistStructure.ViewNode
import android.view.ViewStructure.HtmlInfo
import android.view.autofill.AutofillId

/**
 * Converts an [AssistStructure] into the Android-free [AutofillNode] model and remembers the real
 * [AutofillId] of every node index. The parser never sees framework types, so it is testable on the JVM.
 */
object AndroidStructureReader {

    class Reading(
        val root: AutofillNode,
        val ids: Map<Int, AutofillId>,
        val activityPackage: String?,
    ) {
        operator fun get(index: Int): AutofillId? = ids[index]
    }

    fun read(structure: AssistStructure): Reading? {
        if (structure.windowNodeCount == 0) return null
        val rootView = structure.getWindowNodeAt(0).rootViewNode ?: return null
        val ids = mutableMapOf<Int, AutofillId>()
        var next = 0

        fun convert(node: ViewNode): AutofillNode {
            val index = next++
            node.autofillId?.let { ids[index] = it }
            val children = ArrayList<AutofillNode>(node.childCount)
            for (i in 0 until node.childCount) {
                val child = node.getChildAt(i) ?: continue
                children += convert(child)
            }
            return AutofillNode(
                index = index,
                className = node.className,
                resourceId = node.idEntry?.let { entry ->
                    node.idPackage?.let { "$it:id/$entry" } ?: entry
                },
                hint = node.hint,
                text = node.text?.toString(),
                inputType = node.inputType,
                maxLength = node.maxTextLength,
                autofillHints = node.autofillHints?.toList(),
                htmlInfo = node.htmlInfo?.toModel(),
                webDomain = node.webDomain?.takeIf { it.isNotBlank() },
                webScheme = node.webScheme?.takeIf { it.isNotBlank() },
                isFocused = node.isFocused,
                isEnabled = node.isEnabled,
                children = children,
            )
        }

        val activityPackage = structure.activityComponent?.packageName
        return Reading(convert(rootView), ids, activityPackage)
    }

    private fun HtmlInfo.toModel(): HtmlAttributes {
        val map = attributes?.associate { it.first to it.second }.orEmpty()
        return HtmlAttributes(
            tag = tag,
            type = map["type"],
            name = map["name"],
            id = map["id"],
            autocomplete = map["autocomplete"],
            attributes = map,
        )
    }
}
