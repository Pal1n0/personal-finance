import { configureStore } from '@reduxjs/toolkit'

export const store = configureStore({
  reducer: {
    // Sem pridáme tvoje reducery neskôr (auth, transactions...)
  },
})

// Tieto typy budeš potrebovať všade
export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch