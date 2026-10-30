import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
    AskRequest,
    FeedbackRequest,
    PageRequest,
} from "../../../contracts/v1/generated/types.ts";
import * as api from "./client";

export function useBootstrap() {
    const client = useQueryClient();
    useEffect(
        () => api.onBootstrapRefresh((data) => client.setQueryData(["bootstrap"], data)),
        [client],
    );
    return useQuery({
        queryKey: ["bootstrap"],
        queryFn: api.bootstrap,
        staleTime: Infinity,
        retry: false,
    });
}
export function useAsk() {
    return useMutation({
        mutationFn: ({
            request,
            idempotencyKey,
            signal,
        }: {
            request: AskRequest;
            idempotencyKey?: string;
            signal?: AbortSignal;
        }) => api.ask(request, { idempotencyKey, signal }),
    });
}
export function usePage() {
    return useMutation({
        mutationFn: ({ request, signal }: { request: PageRequest; signal?: AbortSignal }) =>
            api.page(request, { signal }),
    });
}
export function useFeedback() {
    return useMutation({
        mutationFn: ({ request, signal }: { request: FeedbackRequest; signal?: AbortSignal }) =>
            api.feedback(request, { signal }),
    });
}
